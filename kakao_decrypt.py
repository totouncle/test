import argparse
import sys
import os
import sqlite3
from typing import Optional

try:
    from pysqlcipher3 import dbapi2 as sqlcipher
except ImportError as e:
    print("[Error] pysqlcipher3 라이브러리가 설치되지 않았습니다. 'pip install pysqlcipher3'로 설치 후 다시 시도해주세요.")
    sys.exit(1)

from hashlib import pbkdf2_hmac


def derive_key(user_id: str, uuid: str) -> str:
    """사용자 ID와 UUID를 이용해 PBKDF2-HMAC-SHA256으로 키를 파생한다."""
    # TODO: 실제 카카오톡 알고리즘에 맞추어 수정 필요
    salt = (user_id[::-1] + uuid).encode()
    derived = pbkdf2_hmac("sha256", (user_id + uuid).encode(), salt, 100000, dklen=32)
    return derived.hex()


def open_encrypted_db(path: str, key_hex: str) -> sqlcipher.Connection:
    """SQLCipher DB를 열어 커넥션을 반환한다."""
    conn = sqlcipher.connect(path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA cipher_default_compatibility = 3")
    cursor.execute("PRAGMA key = x'{}'".format(key_hex))
    # 키가 올바른지 간단히 확인
    try:
        cursor.execute("SELECT count(*) FROM sqlite_master")
    except sqlcipher.DatabaseError:
        conn.close()
        raise ValueError("DB 복호화 실패: 제공된 키 정보가 올바르지 않습니다.")
    return conn


def create_output_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS rooms (
            room_id TEXT PRIMARY KEY,
            room_name TEXT,
            created_at TEXT,
            member_count INTEGER
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
            msg_id TEXT PRIMARY KEY,
            room_id TEXT,
            sender_id TEXT,
            sender_name TEXT,
            message_text TEXT,
            timestamp INTEGER,
            is_incoming INTEGER,
            attachment_info TEXT,
            FOREIGN KEY(room_id) REFERENCES rooms(room_id)
        )
        """
    )
    conn.commit()
    return conn


def export_data(src_conn: sqlcipher.Connection, dest_conn: sqlite3.Connection, verbose: bool = False):
    s_cur = src_conn.cursor()
    d_cur = dest_conn.cursor()

    # 채팅방 정보 추출 (예시 테이블명: NTChatRoom)
    try:
        for row in s_cur.execute("SELECT room_id, name, created_at FROM NTChatRoom"):
            d_cur.execute(
                "INSERT OR IGNORE INTO rooms(room_id, room_name, created_at) VALUES (?,?,?)",
                (row[0], row[1], row[2])
            )
            if verbose:
                print(f"채팅방 {row[1]} 추출")
    except sqlcipher.DatabaseError:
        if verbose:
            print("[Warn] 채팅방 정보를 가져올 수 없습니다. 테이블 구조가 다를 수 있습니다.")

    # 메시지 추출 (예시 테이블명: NTChatMessage)
    try:
        for row in s_cur.execute(
            """SELECT msg_id, room_id, sender_id, sender_name, message, time, is_incoming, attachment_info FROM NTChatMessage"""
        ):
            d_cur.execute(
                """
                INSERT OR IGNORE INTO messages(msg_id, room_id, sender_id, sender_name, message_text, timestamp, is_incoming, attachment_info)
                VALUES (?,?,?,?,?,?,?,?)
                """,
                row
            )
        if verbose:
            print("메시지 추출 완료")
    except sqlcipher.DatabaseError:
        print("[Error] 메시지 테이블을 읽는 중 오류가 발생했습니다. 스키마가 예상과 다를 수 있습니다.")
        raise

    dest_conn.commit()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="KakaoTalk macOS DB 복호화 스크립트")
    parser.add_argument('-i', '--input', required=True, help='암호화된 KakaoTalk DB 파일 경로')
    parser.add_argument('-o', '--output', default='kakao_decrypted.db', help='출력 SQLite 파일 경로')
    parser.add_argument('--userid', help='카카오톡 사용자 ID')
    parser.add_argument('--uuid', help='디바이스 UUID')
    parser.add_argument('--key', help='직접 제공하는 SQLCipher 키 (hex)')
    parser.add_argument('-v', '--verbose', action='store_true', help='상세 로그 출력')
    return parser.parse_args()


def main():
    args = parse_args()

    if not os.path.exists(args.input):
        print(f"[Error] 입력 DB 파일을 찾을 수 없습니다: {args.input}")
        return

    if args.key:
        key_hex = args.key
    else:
        if not (args.userid and args.uuid):
            print("[Error] 키를 파생하기 위해 --userid와 --uuid를 모두 지정하거나 --key를 사용하세요.")
            return
        key_hex = derive_key(args.userid, args.uuid)

    try:
        src_conn = open_encrypted_db(args.input, key_hex)
    except ValueError as e:
        print(f"[Error] {e}")
        return

    dest_conn = create_output_db(args.output)

    if args.verbose:
        print("데이터 추출 시작...")

    try:
        export_data(src_conn, dest_conn, args.verbose)
    except Exception as e:
        print(f"[Error] 데이터 추출 중 오류가 발생했습니다: {e}")
    finally:
        src_conn.close()
        dest_conn.close()

    if args.verbose:
        print("완료되었습니다.")
    else:
        print("복호화 및 추출 완료.")


if __name__ == '__main__':
    main()
