from typing import Optional
import bcrypt


class PasswordService:
    """Сервис для работы с паролями"""

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Хеширует пароль
        """
        password = password[:72]
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
        return hashed.decode("utf-8")

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """
        Проверяет соответствие пароля хешу
        """
        plain_password = plain_password[:72]
        return bcrypt.checkpw(
            plain_password.encode("utf-8"), hashed_password.encode("utf-8")
        )

    @staticmethod
    def validate_password_strength(password: str) -> tuple[bool, Optional[str]]:
        """
        Проверяет сложность пароля
        """
        if len(password) < 8:
            return False, "Пароль должен быть не менее 8 символов"
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        if not (has_upper and has_lower and has_digit):
            return False, "Пароль должен содержать заглавные, строчные буквы и цифры"
        return True, None


password_service = PasswordService()
