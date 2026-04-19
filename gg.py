from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass, field
import hashlib
import json
import re
import uuid
from enum import Enum

class EmployeeStatus(Enum):
    """Статус сотрудника в системе"""
    ACTIVE = "Активен"
    BLOCKED = "Заблокирован"
    FIRED = "Уволен"
    ON_LEAVE = "В отпуске"


class ConsentStatus(Enum):
    """Статус согласия на обработку ПДн"""
    VALID = "Действует"
    EXPIRING_SOON = "Истекает"
    EXPIRED = "Истекло"
    REVOKED = "Отозвано"


class DataCategory(Enum):
    """Категории персональных данных (для разграничения доступа)"""
    PUBLIC = "Общедоступные"
    PERSONAL = "Персональные"
    SENSITIVE = "Чувствительные"
    BIOMETRIC = "Биометрические"


@dataclass
class EmployeeEntity:
    """Сущность сотрудника в БД"""
    id: int
    full_name: str
    position: str
    department: str
    email: str
    phone: str
    status: EmployeeStatus

    # Персональные данные (чувствительные)
    encrypted_passport: str = ""
    encrypted_snils: str = ""
    encrypted_inn: str = ""
    birth_date: str = ""
    birth_place: str = ""
    address_registration: str = ""
    address_residential: str = ""

    # Метаданные безопасности
    data_categories: Dict[str, DataCategory] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    created_by: str = ""
    updated_by: str = ""

    # Флаги безопасности
    is_sensitive_data_locked: bool = False
    block_reason: str = ""
    failed_login_attempts: int = 0


@dataclass
class ConsentEntity:
    """Согласие на обработку ПДн"""
    id: int
    employee_id: int
    consent_type: str
    granted_date: datetime
    valid_until: datetime
    granted_by: str
    document_number: str
    status: ConsentStatus = ConsentStatus.VALID
    revoked_date: Optional[datetime] = None
    revoked_by: Optional[str] = None

    def check_status(self) -> ConsentStatus:
        """Автоматическое определение статуса согласия"""
        if self.status == ConsentStatus.REVOKED:
            return ConsentStatus.REVOKED
        if self.valid_until < datetime.now():
            return ConsentStatus.EXPIRED
        if self.valid_until < datetime.now() + timedelta(days=30):
            return ConsentStatus.EXPIRING_SOON
        return ConsentStatus.VALID


@dataclass
class UserEntity:
    """Пользователь системы (учетная запись)"""
    id: int
    username: str
    full_name: str
    role: str
    department: str
    encrypted_password: str
    is_active: bool = True
    last_login: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.now)
    permissions: List[str] = field(default_factory=list)


class AuditAction(Enum):
    """Типы действий для аудита"""
    # Сотрудники
    EMPLOYEE_CREATED = "СОЗДАНИЕ_СОТРУДНИКА"
    EMPLOYEE_UPDATED = "ОБНОВЛЕНИЕ_СОТРУДНИКА"
    EMPLOYEE_DELETED = "УДАЛЕНИЕ_СОТРУДНИКА"
    EMPLOYEE_BLOCKED = "БЛОКИРОВКА_СОТРУДНИКА"
    EMPLOYEE_UNBLOCKED = "РАЗБЛОКИРОВКА_СОТРУДНИКА"
    EMPLOYEE_FIRED = "УВОЛЬНЕНИЕ_СОТРУДНИКА"
    EMPLOYEE_VIEWED = "ПРОСМОТР_СОТРУДНИКА"
    SENSITIVE_DATA_ACCESSED = "ДОСТУП_К_ЧУВСТВИТЕЛЬНЫМ_ДАННЫМ"

    # Согласия
    CONSENT_GRANTED = "ПРЕДОСТАВЛЕНИЕ_СОГЛАСИЯ"
    CONSENT_REVOKED = "ОТЗЫВ_СОГЛАСИЯ"

    # Пользователи
    USER_LOGIN = "ВХОД_В_СИСТЕМУ"
    USER_LOGOUT = "ВЫХОД_ИЗ_СИСТЕМЫ"
    USER_CREATED = "СОЗДАНИЕ_ПОЛЬЗОВАТЕЛЯ"
    USER_BLOCKED = "БЛОКИРОВКА_ПОЛЬЗОВАТЕЛЯ"
    USER_ROLE_CHANGED = "ИЗМЕНЕНИЕ_РОЛИ_ПОЛЬЗОВАТЕЛЯ"

    # Безопасность
    ACCESS_DENIED = "ДОСТУП_ЗАПРЕЩЕН"
    SECURITY_ALERT = "ТРЕВОГА_БЕЗОПАСНОСТИ"
    DATA_EXPORT = "ЭКСПОРТ_ДАННЫХ"


@dataclass
class AuditLogEntry:
    """Запись аудита"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    user: str = ""
    user_role: str = ""
    action: AuditAction = None
    target_type: str = ""
    target_id: int = 0
    details: Dict = field(default_factory=dict)
    ip_address: str = "127.0.0.1"
    result: str = "SUCCESS"
    error_message: str = ""


#DATA ACCESS LAYER

class SecureEmployeeRepository:
    def __init__(self):
        self._employees: Dict[int, EmployeeEntity] = {}
        self._consents: Dict[int, List[ConsentEntity]] = {}
        self._users: Dict[int, UserEntity] = {}
        self._next_employee_id = 1
        self._next_consent_id = 1
        self._next_user_id = 1

        print("[DataAccess] Инициализация репозитория. Подключение к PostgreSQL (SSL/TLS).")

    def create_employee(self, employee: EmployeeEntity) -> EmployeeEntity:
        """Создание нового сотрудника"""
        employee.id = self._next_employee_id
        self._next_employee_id += 1
        employee.created_at = datetime.now()
        employee.updated_at = datetime.now()

        self._employees[employee.id] = employee
        self._consents[employee.id] = []

        print(f"[DataAccess] INSERT INTO Employees (id={employee.id}, name={employee.full_name})")
        return employee

    def get_by_id(self, employee_id: int) -> Optional[EmployeeEntity]:
        """Получение сотрудника по ID"""
        print(f"[DataAccess] SELECT * FROM Employees WHERE id = {employee_id}")
        return self._employees.get(employee_id)

    def get_all_employees(self, include_fired: bool = False) -> List[EmployeeEntity]:
        """Получение списка всех сотрудников"""
        print(f"[DataAccess] SELECT * FROM Employees (include_fired={include_fired})")
        employees = list(self._employees.values())
        if not include_fired:
            employees = [e for e in employees if e.status != EmployeeStatus.FIRED]
        return employees

    def search_employees(self, query: str) -> List[EmployeeEntity]:
        """Поиск сотрудников по ФИО, email, должности"""
        query_lower = query.lower()
        results = []
        for emp in self._employees.values():
            if (query_lower in emp.full_name.lower() or
                    query_lower in emp.email.lower() or
                    query_lower in emp.position.lower() or
                    query_lower in emp.department.lower()):
                results.append(emp)
        print(f"[DataAccess] SEARCH Employees: найдено {len(results)} записей")
        return results

    def update_employee(self, employee: EmployeeEntity) -> bool:
        """Обновление данных сотрудника"""
        if employee.id not in self._employees:
            return False

        employee.updated_at = datetime.now()
        self._employees[employee.id] = employee

        print(f"[DataAccess] UPDATE Employees SET ... WHERE id = {employee.id}")
        return True

    def delete_employee(self, employee_id: int, hard_delete: bool = False) -> bool:
        """Удаление сотрудника (мягкое или жесткое)"""
        if employee_id not in self._employees:
            return False

        if hard_delete:
            del self._employees[employee_id]
            if employee_id in self._consents:
                del self._consents[employee_id]
            print(f"[DataAccess] DELETE FROM Employees WHERE id = {employee_id} (HARD DELETE)")
        else:
            self._employees[employee_id].status = EmployeeStatus.FIRED
            self._employees[employee_id].updated_at = datetime.now()
            print(f"[DataAccess] UPDATE Employees SET status = 'FIRED' WHERE id = {employee_id}")

        return True

    def block_employee(self, employee_id: int, reason: str) -> bool:
        """Блокировка сотрудника"""
        if employee_id not in self._employees:
            return False

        self._employees[employee_id].status = EmployeeStatus.BLOCKED
        self._employees[employee_id].block_reason = reason
        self._employees[employee_id].updated_at = datetime.now()

        print(f"[DataAccess] UPDATE Employees SET status = 'BLOCKED' WHERE id = {employee_id}")
        return True

    def unblock_employee(self, employee_id: int) -> bool:
        """Разблокировка сотрудника"""
        if employee_id not in self._employees:
            return False

        self._employees[employee_id].status = EmployeeStatus.ACTIVE
        self._employees[employee_id].block_reason = ""
        self._employees[employee_id].failed_login_attempts = 0
        self._employees[employee_id].updated_at = datetime.now()

        print(f"[DataAccess] UPDATE Employees SET status = 'ACTIVE' WHERE id = {employee_id}")
        return True

    def create_consent(self, consent: ConsentEntity) -> ConsentEntity:
        """Создание нового согласия"""
        consent.id = self._next_consent_id
        self._next_consent_id += 1

        if consent.employee_id not in self._consents:
            self._consents[consent.employee_id] = []

        self._consents[consent.employee_id].append(consent)

        print(f"[DataAccess] INSERT INTO Consents (id={consent.id}, employee_id={consent.employee_id})")
        return consent

    def get_employee_consents(self, employee_id: int) -> List[ConsentEntity]:
        """Получение всех согласий сотрудника"""
        return self._consents.get(employee_id, [])

    def revoke_consent(self, consent_id: int, revoked_by: str) -> bool:
        """Отзыв согласия"""
        for consents in self._consents.values():
            for consent in consents:
                if consent.id == consent_id:
                    consent.status = ConsentStatus.REVOKED
                    consent.revoked_date = datetime.now()
                    consent.revoked_by = revoked_by
                    print(f"[DataAccess] UPDATE Consents SET status = 'REVOKED' WHERE id = {consent_id}")
                    return True
        return False

    def create_user(self, user: UserEntity) -> UserEntity:
        """Создание пользователя системы"""
        user.id = self._next_user_id
        self._next_user_id += 1

        user.encrypted_password = self._hash_password(user.encrypted_password)

        self._users[user.id] = user
        print(f"[DataAccess] INSERT INTO Users (id={user.id}, username={user.username})")
        return user

    def get_user_by_username(self, username: str) -> Optional[UserEntity]:
        """Поиск пользователя по логину"""
        for user in self._users.values():
            if user.username == username:
                return user
        return None

    def get_all_users(self) -> List[UserEntity]:
        """Получение всех пользователей системы"""
        return list(self._users.values())

    def update_user(self, user: UserEntity) -> bool:
        """Обновление пользователя"""
        if user.id not in self._users:
            return False
        self._users[user.id] = user
        return True

    def block_user(self, user_id: int) -> bool:
        """Блокировка пользователя"""
        if user_id not in self._users:
            return False
        self._users[user_id].is_active = False
        return True

    def _hash_password(self, password: str) -> str:
        """Хеширование пароля (имитация)"""
        return hashlib.sha256(password.encode()).hexdigest()

    def verify_password(self, username: str, password: str) -> Tuple[bool, Optional[UserEntity]]:
        """Проверка пароля пользователя"""
        user = self.get_user_by_username(username)
        if not user or not user.is_active:
            return False, None

        password_hash = self._hash_password(password)
        if user.encrypted_password == password_hash:
            user.last_login = datetime.now()
            return True, user

        return False, None


    def get_statistics(self) -> Dict:
        """Получение статистики по БД"""
        total_employees = len(self._employees)
        active_employees = sum(1 for e in self._employees.values() if e.status == EmployeeStatus.ACTIVE)
        blocked_employees = sum(1 for e in self._employees.values() if e.status == EmployeeStatus.BLOCKED)
        fired_employees = sum(1 for e in self._employees.values() if e.status == EmployeeStatus.FIRED)

        total_consents = sum(len(c) for c in self._consents.values())
        expired_consents = 0
        for consents in self._consents.values():
            for c in consents:
                if c.check_status() == ConsentStatus.EXPIRED:
                    expired_consents += 1

        return {
            'total_employees': total_employees,
            'active_employees': active_employees,
            'blocked_employees': blocked_employees,
            'fired_employees': fired_employees,
            'total_consents': total_consents,
            'expired_consents': expired_consents,
            'total_users': len(self._users)
        }


class AuditRepository:

    def __init__(self):
        self._audit_logs: List[AuditLogEntry] = []
        print("[DataAccess] Инициализация репозитория аудита.")

    def add_entry(self, entry: AuditLogEntry) -> None:
        """Добавление записи в аудит"""
        self._audit_logs.append(entry)
        print(f"[DataAccess] INSERT INTO AuditLog (id={entry.id}, action={entry.action.value})")

    def get_all_logs(self) -> List[AuditLogEntry]:
        """Получение всех записей аудита"""
        return self._audit_logs.copy()

    def get_logs_by_user(self, username: str) -> List[AuditLogEntry]:
        """Фильтрация аудита по пользователю"""
        return [log for log in self._audit_logs if log.user == username]

    def get_logs_by_action(self, action: AuditAction) -> List[AuditLogEntry]:
        """Фильтрация аудита по типу действия"""
        return [log for log in self._audit_logs if log.action == action]

    def get_logs_by_date_range(self, start_date: datetime, end_date: datetime) -> List[AuditLogEntry]:
        """Фильтрация аудита по дате"""
        return [log for log in self._audit_logs
                if start_date <= log.timestamp <= end_date]

    def get_security_alerts(self) -> List[AuditLogEntry]:
        """Получение записей о нарушениях безопасности"""
        alerts = []
        for log in self._audit_logs:
            if (log.action == AuditAction.ACCESS_DENIED or
                    log.action == AuditAction.SECURITY_ALERT or
                    log.result == "FAILURE"):
                alerts.append(log)
        return alerts

    def clear_old_logs(self, days: int = 365) -> int:
        """Очистка старых логов (старше N дней)"""
        cutoff_date = datetime.now() - timedelta(days=days)
        old_count = len([log for log in self._audit_logs if log.timestamp < cutoff_date])
        self._audit_logs = [log for log in self._audit_logs if log.timestamp >= cutoff_date]
        print(f"[DataAccess] DELETE FROM AuditLog WHERE timestamp < {cutoff_date} ({old_count} записей)")
        return old_count


#BUSINESS LOGIC LAYER

class EncryptionService:
    """Сервис шифрования чувствительных данных"""

    @staticmethod
    def encrypt_data(data: str) -> str:
        """Шифрование данных (AES-256 имитация)"""
        if not data:
            return ""
        hash_obj = hashlib.sha256(data.encode())
        return f"AES256:{hash_obj.hexdigest()[:32]}"

    @staticmethod
    def mask_passport(encrypted: str) -> str:
        """Маскирование паспорта"""
        return "**** ******"

    @staticmethod
    def mask_snils(encrypted: str) -> str:
        """Маскирование СНИЛС"""
        return "***-***-*** **"

    @staticmethod
    def mask_phone(phone: str) -> str:
        """Маскирование телефона"""
        if len(phone) > 4:
            return f"+7 (***) ***-{phone[-4:]}"
        return "***"

    @staticmethod
    def mask_email(email: str) -> str:
        """Маскирование email"""
        if '@' in email:
            local, domain = email.split('@')
            if len(local) > 3:
                return f"{local[:2]}***@{domain}"
        return "***@***.***"


class ConsentValidator:
    """Валидатор согласий на обработку ПДн"""

    @staticmethod
    def validate_consents(employee_id: int, consents: List[ConsentEntity]) -> Tuple[bool, List[str]]:
        """ Проверка всех согласий сотрудника """
        problems = []

        consent_types = {c.consent_type for c in consents if c.check_status() == ConsentStatus.VALID}
        required_types = {"processing", "transfer"}

        for req_type in required_types:
            if req_type not in consent_types:
                problems.append(f"Отсутствует действующее согласие на {req_type}")

        for consent in consents:
            status = consent.check_status()
            if status == ConsentStatus.EXPIRED:
                problems.append(f"Согласие {consent.consent_type} истекло {consent.valid_until.strftime('%d.%m.%Y')}")
            elif status == ConsentStatus.EXPIRING_SOON:
                days_left = (consent.valid_until - datetime.now()).days
                problems.append(f"Согласие {consent.consent_type} истекает через {days_left} дн.")
            elif status == ConsentStatus.REVOKED:
                problems.append(f"Согласие {consent.consent_type} отозвано")

        is_valid = len([p for p in problems if
                        "истекло" in p.lower() or "отозвано" in p.lower() or "отсутствует" in p.lower()]) == 0
        return is_valid, problems


class EmployeeDataService:

    # Матрица доступа: роль -> разрешенные действия
    ROLE_PERMISSIONS = {
        'HR_Admin': {
            'can_create_employee': True,
            'can_edit_employee': True,
            'can_delete_employee': False,  # Только FIRED статус
            'can_hard_delete': False,
            'can_block_employee': True,
            'can_view_sensitive_data': True,
            'can_manage_consents': True,
            'can_manage_users': False,
            'can_view_audit': True,
            'can_export_data': True
        },
        'Security_Officer': {
            'can_create_employee': False,
            'can_edit_employee': False,
            'can_delete_employee': True,
            'can_hard_delete': True,
            'can_block_employee': True,
            'can_view_sensitive_data': True,
            'can_manage_consents': False,
            'can_manage_users': True,
            'can_view_audit': True,
            'can_export_data': True
        },
        'Data_Protection_Officer': {
            'can_create_employee': False,
            'can_edit_employee': False,
            'can_delete_employee': False,
            'can_hard_delete': False,
            'can_block_employee': False,
            'can_view_sensitive_data': True,
            'can_manage_consents': True,
            'can_manage_users': False,
            'can_view_audit': True,
            'can_export_data': False
        },
        'Manager': {
            'can_create_employee': False,
            'can_edit_employee': False,
            'can_delete_employee': False,
            'can_hard_delete': False,
            'can_block_employee': False,
            'can_view_sensitive_data': False,
            'can_manage_consents': False,
            'can_manage_users': False,
            'can_view_audit': False,
            'can_export_data': False
        }
    }

    def __init__(self, employee_repo: SecureEmployeeRepository, audit_repo: AuditRepository,
                 current_user: UserEntity):
        self._emp_repo = employee_repo
        self._audit_repo = audit_repo
        self._current_user = current_user
        self._crypto = EncryptionService()
        self._validator = ConsentValidator()
        self._permissions = self.ROLE_PERMISSIONS.get(current_user.role, {})

        print(f"[BusinessLogic] Сервис инициализирован: {current_user.full_name} ({current_user.role})")

    def _check_permission(self, permission: str) -> Tuple[bool, str]:
        """Проверка наличия разрешения"""
        if self._permissions.get(permission, False):
            return True, ""

        msg = f"Доступ запрещен: отсутствует разрешение '{permission}'"
        self._audit_repo.add_entry(AuditLogEntry(
            user=self._current_user.username,
            user_role=self._current_user.role,
            action=AuditAction.ACCESS_DENIED,
            target_type="Permission",
            details={'permission': permission},
            result="FAILURE",
            error_message=msg
        ))
        return False, msg

    def _check_consents(self, employee_id: int) -> Tuple[bool, str]:
        """Проверка согласий сотрудника"""
        consents = self._emp_repo.get_employee_consents(employee_id)
        is_valid, problems = self._validator.validate_consents(employee_id, consents)

        if not is_valid:
            critical_problems = [p for p in problems if
                                 "истекло" in p.lower() or "отозвано" in p.lower() or "отсутствует" in p.lower()]
            if critical_problems:
                return False, "\n".join(critical_problems)

        return True, ""

    def create_employee(self, data: Dict) -> Tuple[bool, str, Optional[EmployeeEntity]]:
        """Создание нового сотрудника"""
        # Проверка прав
        has_permission, error = self._check_permission('can_create_employee')
        if not has_permission:
            return False, error, None

        # Валидация обязательных полей
        required_fields = ['full_name', 'position', 'department', 'email', 'phone']
        missing_fields = [f for f in required_fields if not data.get(f)]
        if missing_fields:
            return False, f"Отсутствуют обязательные поля: {', '.join(missing_fields)}", None

        # Проверка формата email
        if not self._validate_email(data['email']):
            return False, "Неверный формат email", None

        # Проверка формата телефона
        if not self._validate_phone(data['phone']):
            return False, "Неверный формат телефона", None

        # Создание сотрудника
        employee = EmployeeEntity(
            id=0,
            full_name=data['full_name'],
            position=data['position'],
            department=data['department'],
            email=data['email'],
            phone=data['phone'],
            status=EmployeeStatus.ACTIVE,
            created_by=self._current_user.username,
            updated_by=self._current_user.username
        )

        # Шифрование персональных данных, если они предоставлены
        if data.get('passport'):
            employee.encrypted_passport = self._crypto.encrypt_data(data['passport'])
        if data.get('snils'):
            employee.encrypted_snils = self._crypto.encrypt_data(data['snils'])
        if data.get('inn'):
            employee.encrypted_inn = self._crypto.encrypt_data(data['inn'])
        if data.get('birth_date'):
            employee.birth_date = data['birth_date']
        if data.get('birth_place'):
            employee.birth_place = data['birth_place']
        if data.get('address'):
            employee.address_registration = data['address']

        # Сохранение
        created_employee = self._emp_repo.create_employee(employee)

        # Создание обязательного согласия на обработку ПДн
        consent = ConsentEntity(
            id=0,
            employee_id=created_employee.id,
            consent_type="processing",
            granted_date=datetime.now(),
            valid_until=datetime.now() + timedelta(days=365),
            granted_by=self._current_user.username,
            document_number=f"CONS-{created_employee.id}-{datetime.now().year}"
        )
        self._emp_repo.create_consent(consent)

        # Аудит
        self._audit_repo.add_entry(AuditLogEntry(
            user=self._current_user.username,
            user_role=self._current_user.role,
            action=AuditAction.EMPLOYEE_CREATED,
            target_type="Employee",
            target_id=created_employee.id,
            details={'employee_name': created_employee.full_name}
        ))

        return True, f"Сотрудник {created_employee.full_name} успешно создан (ID: {created_employee.id})", created_employee

    def get_employee(self, employee_id: int, include_sensitive: bool = False) -> Tuple[bool, str, Optional[Dict]]:
        """Получение данных сотрудника"""
        employee = self._emp_repo.get_by_id(employee_id)
        if not employee:
            return False, f"Сотрудник с ID {employee_id} не найден", None

        # Проверка прав на просмотр чувствительных данных
        if include_sensitive:
            has_permission, error = self._check_permission('can_view_sensitive_data')
            if not has_permission:
                include_sensitive = False

        # Проверка согласий
        consents_valid, consent_error = self._check_consents(employee_id)
        if not consents_valid:
            return False, f"Доступ к данным запрещен:\n{consent_error}", None

        # Формирование ответа
        result = {
            'id': employee.id,
            'full_name': employee.full_name,
            'position': employee.position,
            'department': employee.department,
            'email': self._crypto.mask_email(employee.email) if not include_sensitive else employee.email,
            'phone': self._crypto.mask_phone(employee.phone) if not include_sensitive else employee.phone,
            'status': employee.status.value,
            'created_at': employee.created_at.strftime('%d.%m.%Y %H:%M'),
            'updated_at': employee.updated_at.strftime('%d.%m.%Y %H:%M')
        }

        if include_sensitive:
            result.update({
                'passport': self._crypto.mask_passport(employee.encrypted_passport),
                'snils': self._crypto.mask_snils(employee.encrypted_snils),
                'birth_date': employee.birth_date,
                'birth_place': employee.birth_place,
                'address': employee.address_registration
            })

        # Аудит
        self._audit_repo.add_entry(AuditLogEntry(
            user=self._current_user.username,
            user_role=self._current_user.role,
            action=AuditAction.EMPLOYEE_VIEWED if not include_sensitive else AuditAction.SENSITIVE_DATA_ACCESSED,
            target_type="Employee",
            target_id=employee_id,
            details={'include_sensitive': include_sensitive}
        ))

        return True, "", result

    def get_all_employees(self) -> Tuple[bool, str, List[Dict]]:
        """Получение списка всех сотрудников"""
        employees = self._emp_repo.get_all_employees()
        result = []

        for emp in employees:
            result.append({
                'id': emp.id,
                'full_name': emp.full_name,
                'position': emp.position,
                'department': emp.department,
                'status': emp.status.value,
                'email': self._crypto.mask_email(emp.email),
                'phone': self._crypto.mask_phone(emp.phone)
            })

        return True, f"Найдено сотрудников: {len(result)}", result

    def search_employees(self, query: str) -> Tuple[bool, str, List[Dict]]:
        """Поиск сотрудников"""
        if not query or len(query) < 2:
            return False, "Поисковый запрос должен содержать минимум 2 символа", []

        employees = self._emp_repo.search_employees(query)
        result = []

        for emp in employees:
            result.append({
                'id': emp.id,
                'full_name': emp.full_name,
                'position': emp.position,
                'department': emp.department,
                'status': emp.status.value
            })

        # Аудит
        self._audit_repo.add_entry(AuditLogEntry(
            user=self._current_user.username,
            user_role=self._current_user.role,
            action=AuditAction.EMPLOYEE_VIEWED,
            target_type="Employee",
            details={'search_query': query, 'results_count': len(result)}
        ))

        return True, f"Найдено сотрудников: {len(result)}", result

    def update_employee(self, employee_id: int, data: Dict) -> Tuple[bool, str]:
        """Обновление данных сотрудника"""
        # Проверка прав
        has_permission, error = self._check_permission('can_edit_employee')
        if not has_permission:
            return False, error

        employee = self._emp_repo.get_by_id(employee_id)
        if not employee:
            return False, f"Сотрудник с ID {employee_id} не найден"

        # Проверка статуса
        if employee.status in [EmployeeStatus.FIRED, EmployeeStatus.BLOCKED]:
            return False, f"Невозможно редактировать сотрудника со статусом '{employee.status.value}'"

        # Обновление полей
        if 'full_name' in data:
            employee.full_name = data['full_name']
        if 'position' in data:
            employee.position = data['position']
        if 'department' in data:
            employee.department = data['department']
        if 'email' in data and self._validate_email(data['email']):
            employee.email = data['email']
        if 'phone' in data and self._validate_phone(data['phone']):
            employee.phone = data['phone']
        if 'passport' in data:
            employee.encrypted_passport = self._crypto.encrypt_data(data['passport'])
        if 'snils' in data:
            employee.encrypted_snils = self._crypto.encrypt_data(data['snils'])
        if 'address' in data:
            employee.address_registration = data['address']

        employee.updated_by = self._current_user.username
        employee.updated_at = datetime.now()

        self._emp_repo.update_employee(employee)

        # Аудит
        self._audit_repo.add_entry(AuditLogEntry(
            user=self._current_user.username,
            user_role=self._current_user.role,
            action=AuditAction.EMPLOYEE_UPDATED,
            target_type="Employee",
            target_id=employee_id,
            details={'updated_fields': list(data.keys())}
        ))

        return True, f"Данные сотрудника {employee.full_name} обновлены"

    def delete_employee(self, employee_id: int, hard_delete: bool = False) -> Tuple[bool, str]:
        """Удаление сотрудника"""
        # Проверка прав
        permission = 'can_hard_delete' if hard_delete else 'can_delete_employee'
        has_permission, error = self._check_permission(permission)
        if not has_permission:
            return False, error

        employee = self._emp_repo.get_by_id(employee_id)
        if not employee:
            return False, f"Сотрудник с ID {employee_id} не найден"

        # Проверка, что сотрудник уже уволен (для жесткого удаления)
        if hard_delete and employee.status != EmployeeStatus.FIRED:
            return False, "Жесткое удаление возможно только для уволенных сотрудников"

        self._emp_repo.delete_employee(employee_id, hard_delete)

        # Аудит
        action = AuditAction.EMPLOYEE_DELETED
        details = {'employee_name': employee.full_name, 'hard_delete': hard_delete}

        self._audit_repo.add_entry(AuditLogEntry(
            user=self._current_user.username,
            user_role=self._current_user.role,
            action=action,
            target_type="Employee",
            target_id=employee_id,
            details=details
        ))

        return True, f"Сотрудник {employee.full_name} {'полностью удален' if hard_delete else 'помечен как уволенный'}"

    def block_employee(self, employee_id: int, reason: str) -> Tuple[bool, str]:
        """Блокировка сотрудника"""
        has_permission, error = self._check_permission('can_block_employee')
        if not has_permission:
            return False, error

        employee = self._emp_repo.get_by_id(employee_id)
        if not employee:
            return False, f"Сотрудник с ID {employee_id} не найден"

        self._emp_repo.block_employee(employee_id, reason)

        # Аудит
        self._audit_repo.add_entry(AuditLogEntry(
            user=self._current_user.username,
            user_role=self._current_user.role,
            action=AuditAction.EMPLOYEE_BLOCKED,
            target_type="Employee",
            target_id=employee_id,
            details={'employee_name': employee.full_name, 'reason': reason}
        ))

        return True, f"Сотрудник {employee.full_name} заблокирован"

    def unblock_employee(self, employee_id: int) -> Tuple[bool, str]:
        """Разблокировка сотрудника"""
        has_permission, error = self._check_permission('can_block_employee')
        if not has_permission:
            return False, error

        employee = self._emp_repo.get_by_id(employee_id)
        if not employee:
            return False, f"Сотрудник с ID {employee_id} не найден"

        self._emp_repo.unblock_employee(employee_id)

        # Аудит
        self._audit_repo.add_entry(AuditLogEntry(
            user=self._current_user.username,
            user_role=self._current_user.role,
            action=AuditAction.EMPLOYEE_UNBLOCKED,
            target_type="Employee",
            target_id=employee_id,
            details={'employee_name': employee.full_name}
        ))

        return True, f"Сотрудник {employee.full_name} разблокирован"

    def grant_consent(self, employee_id: int, consent_type: str, valid_days: int = 365) -> Tuple[bool, str]:
        """Предоставление согласия на обработку ПДн"""
        has_permission, error = self._check_permission('can_manage_consents')
        if not has_permission:
            return False, error

        employee = self._emp_repo.get_by_id(employee_id)
        if not employee:
            return False, f"Сотрудник с ID {employee_id} не найден"

        consent = ConsentEntity(
            id=0,
            employee_id=employee_id,
            consent_type=consent_type,
            granted_date=datetime.now(),
            valid_until=datetime.now() + timedelta(days=valid_days),
            granted_by=self._current_user.username,
            document_number=f"CONS-{employee_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        )

        self._emp_repo.create_consent(consent)

        # Аудит
        self._audit_repo.add_entry(AuditLogEntry(
            user=self._current_user.username,
            user_role=self._current_user.role,
            action=AuditAction.CONSENT_GRANTED,
            target_type="Consent",
            target_id=employee_id,
            details={'consent_type': consent_type, 'valid_days': valid_days}
        ))

        return True, f"Согласие {consent_type} предоставлено до {consent.valid_until.strftime('%d.%m.%Y')}"

    def revoke_consent(self, consent_id: int) -> Tuple[bool, str]:
        """Отзыв согласия"""
        has_permission, error = self._check_permission('can_manage_consents')
        if not has_permission:
            return False, error

        if self._emp_repo.revoke_consent(consent_id, self._current_user.username):
            # Аудит
            self._audit_repo.add_entry(AuditLogEntry(
                user=self._current_user.username,
                user_role=self._current_user.role,
                action=AuditAction.CONSENT_REVOKED,
                target_type="Consent",
                target_id=consent_id,
                details={}
            ))
            return True, f"Согласие #{consent_id} отозвано"

        return False, f"Согласие #{consent_id} не найдено"

    def get_employee_consents(self, employee_id: int) -> Tuple[bool, str, List[Dict]]:
        """Получение согласий сотрудника"""
        employee = self._emp_repo.get_by_id(employee_id)
        if not employee:
            return False, f"Сотрудник с ID {employee_id} не найден", []

        consents = self._emp_repo.get_employee_consents(employee_id)
        result = []

        for c in consents:
            result.append({
                'id': c.id,
                'type': c.consent_type,
                'granted_date': c.granted_date.strftime('%d.%m.%Y'),
                'valid_until': c.valid_until.strftime('%d.%m.%Y'),
                'status': c.check_status().value,
                'granted_by': c.granted_by,
                'document': c.document_number
            })

        return True, f"Найдено согласий: {len(result)}", result

    def create_user(self, username: str, password: str, full_name: str, role: str, department: str) -> Tuple[
        bool, str, Optional[UserEntity]]:
        """Создание пользователя системы"""
        has_permission, error = self._check_permission('can_manage_users')
        if not has_permission:
            return False, error, None

        # Проверка существования пользователя
        existing = self._emp_repo.get_user_by_username(username)
        if existing:
            return False, f"Пользователь {username} уже существует", None

        # Проверка допустимости роли
        if role not in self.ROLE_PERMISSIONS:
            return False, f"Недопустимая роль: {role}", None

        user = UserEntity(
            id=0,
            username=username,
            full_name=full_name,
            role=role,
            department=department,
            encrypted_password=password,  # Будет захэшировано в репозитории
            is_active=True
        )

        created_user = self._emp_repo.create_user(user)

        # Аудит
        self._audit_repo.add_entry(AuditLogEntry(
            user=self._current_user.username,
            user_role=self._current_user.role,
            action=AuditAction.USER_CREATED,
            target_type="User",
            target_id=created_user.id,
            details={'username': username, 'role': role}
        ))

        return True, f"Пользователь {username} создан", created_user

    def get_all_users(self) -> Tuple[bool, str, List[Dict]]:
        """Получение списка пользователей"""
        has_permission, error = self._check_permission('can_manage_users')
        if not has_permission:
            return False, error, []

        users = self._emp_repo.get_all_users()
        result = []

        for u in users:
            result.append({
                'id': u.id,
                'username': u.username,
                'full_name': u.full_name,
                'role': u.role,
                'department': u.department,
                'is_active': u.is_active,
                'last_login': u.last_login.strftime('%d.%m.%Y %H:%M') if u.last_login else 'Никогда'
            })

        return True, f"Пользователей: {len(result)}", result

    def block_user(self, user_id: int) -> Tuple[bool, str]:
        """Блокировка пользователя"""
        has_permission, error = self._check_permission('can_manage_users')
        if not has_permission:
            return False, error

        if self._emp_repo.block_user(user_id):
            # Аудит
            self._audit_repo.add_entry(AuditLogEntry(
                user=self._current_user.username,
                user_role=self._current_user.role,
                action=AuditAction.USER_BLOCKED,
                target_type="User",
                target_id=user_id,
                details={}
            ))
            return True, f"Пользователь #{user_id} заблокирован"

        return False, f"Пользователь #{user_id} не найден"

    def get_audit_logs(self, filter_type: str = "all") -> Tuple[bool, str, List[Dict]]:
        """Получение журнала аудита"""
        has_permission, error = self._check_permission('can_view_audit')
        if not has_permission:
            return False, error, []

        if filter_type == "security":
            logs = self._audit_repo.get_security_alerts()
        elif filter_type == "my":
            logs = self._audit_repo.get_logs_by_user(self._current_user.username)
        else:
            logs = self._audit_repo.get_all_logs()

        result = []
        for log in logs[-50:]:
            result.append({
                'timestamp': log.timestamp.strftime('%d.%m.%Y %H:%M:%S'),
                'user': log.user,
                'action': log.action.value if log.action else 'UNKNOWN',
                'target': f"{log.target_type}:{log.target_id}",
                'result': log.result,
                'details': json.dumps(log.details, ensure_ascii=False) if log.details else ''
            })

        return True, f"Записей: {len(result)}", result

    def get_statistics(self) -> Tuple[bool, str, Dict]:
        """Получение статистики системы"""
        stats = self._emp_repo.get_statistics()

        # Дополнительная статистика по аудиту
        all_logs = self._audit_repo.get_all_logs()
        security_alerts = self._audit_repo.get_security_alerts()

        stats.update({
            'total_audit_records': len(all_logs),
            'security_alerts_today': len([a for a in security_alerts
                                          if a.timestamp.date() == datetime.now().date()]),
            'active_users': sum(1 for u in self._emp_repo.get_all_users() if u.is_active)
        })

        return True, "Статистика собрана", stats


    def _validate_email(self, email: str) -> bool:
        """Валидация email"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    def _validate_phone(self, phone: str) -> bool:
        """Валидация телефона"""
        pattern = r'^\+?\d{10,12}$'
        return bool(re.match(pattern, re.sub(r'[\s\-\(\)]', '', phone)))


#PRESENTATION LAYER

class ConsoleUI:
    """Консольный интерфейс пользователя"""

    def __init__(self):
        self._emp_repo: Optional[SecureEmployeeRepository] = None
        self._audit_repo: Optional[AuditRepository] = None
        self._service: Optional[EmployeeDataService] = None
        self._current_user: Optional[UserEntity] = None

    def _print_header(self, title: str):
        """Отображение заголовка"""
        print("\n" + "=" * 70)
        print(f"  {title}")
        print("=" * 70)

    def _print_security_banner(self):
        """Баннер безопасности"""
        print("""
╔══════════════════════════════════════════════════════════════════════╗
║  ВНИМАНИЕ! ИНФОРМАЦИОННАЯ СИСТЕМА ПЕРСОНАЛЬНЫХ ДАННЫХ (ИСПДн)        ║
║  Класс защищенности: К1                                              ║
║  Все действия протоколируются.                                       ║
║  Несанкционированный доступ преследуется по ст. 137, 272, 274 УК РФ. ║
╚══════════════════════════════════════════════════════════════════════╝
        """)

    def _login(self) -> bool:
        """Вход в систему"""
        self._print_header("АУТЕНТИФИКАЦИЯ")

        print("\nДоступные тестовые пользователи:")
        print("┌─────┬──────────────┬─────────────────────┬─────────────────────┐")
        print("│ №   │ Логин        │ Роль                │ ФИО                 │")
        print("├─────┼──────────────┼─────────────────────┼─────────────────────┤")
        print("│ 1   │ admin        │ жесткий Босс            │ Петроченко М.Р. │")
        print("│ 2   │ security     │ Security_Officer    │ Иванов С.Б.         │")
        print("│ 3   │ dpo          │ Data_Protection_Officer│ Смирнова Д.В.    │")
        print("│ 4   │ manager1     │ Manager             │ Кузнецов М.А.       │")
        print("└─────┴──────────────┴─────────────────────┴─────────────────────┘")

        username = input("\nЛогин: ").strip()
        password = input("Пароль: ").strip()

        success, user = self._emp_repo.verify_password(username, password)

        if success:
            self._current_user = user
            self._service = EmployeeDataService(self._emp_repo, self._audit_repo, user)

            # Аудит входа
            self._audit_repo.add_entry(AuditLogEntry(
                user=user.username,
                user_role=user.role,
                action=AuditAction.USER_LOGIN,
                target_type="User",
                target_id=user.id
            ))

            print(f"\n[УСПЕХ] Добро пожаловать, {user.full_name} ({user.role})")
            return True

        print("\n[ОШИБКА] Неверный логин или пароль")
        return False

    def _init_repositories(self):
        """Инициализация репозиториев и тестовых данных"""
        print("\n[INFO] Инициализация системы...")

        self._emp_repo = SecureEmployeeRepository()
        self._audit_repo = AuditRepository()

        # Создание тестовых пользователей
        self._emp_repo.create_user(UserEntity(
            id=0, username="admin", full_name="Петроченко Маргарита Романовна",
            role="Жесткий босс", department="HR", encrypted_password="123456"
        ))
        self._emp_repo.create_user(UserEntity(
            id=0, username="security", full_name="Иванов Сергей Борисович",
            role="Security_Officer", department="СБ", encrypted_password="123456"
        ))
        self._emp_repo.create_user(UserEntity(
            id=0, username="dpo", full_name="Смирнова Дарья Владимировна",
            role="Data_Protection_Officer", department="Юридический", encrypted_password="123456"
        ))
        self._emp_repo.create_user(UserEntity(
            id=0, username="manager1", full_name="Кузнецов Михаил Александрович",
            role="Manager", department="ИТ", encrypted_password="123456"
        ))

        # Создание тестовых сотрудников
        service_temp = EmployeeDataService(
            self._emp_repo, self._audit_repo,
            self._emp_repo.get_user_by_username("admin")
        )

        service_temp.create_employee({
            'full_name': 'Соколов Андрей Викторович',
            'position': 'Ведущий разработчик',
            'department': 'ИТ',
            'email': 'sokolov@company.ru',
            'phone': '9161234567',
            'passport': '4510 123456',
            'snils': '123-456-789 01',
            'inn': '770123456789',
            'birth_date': '15.03.1985',
            'birth_place': 'г. Москва',
            'address': 'г. Москва, ул. Ленина, д. 10, кв. 45'
        })

        service_temp.create_employee({
            'full_name': 'Морозова Елена Игоревна',
            'position': 'Главный бухгалтер',
            'department': 'Бухгалтерия',
            'email': 'morozova@company.ru',
            'phone': '9037654321',
            'passport': '4511 654321',
            'snils': '987-654-321 09'
        })

        success, msg, emp3 = service_temp.create_employee({
            'full_name': 'Волков Дмитрий Сергеевич',
            'position': 'Менеджер по продажам',
            'department': 'Продажи',
            'email': 'volkov@company.ru',
            'phone': '9265554433'
        })

        print("[INFO] Система готова к работе")

    def _show_main_menu(self) -> str:
        """Главное меню"""
        self._print_header(f"ГЛАВНОЕ МЕНЮ | {self._current_user.full_name} ({self._current_user.role})")

        menu_items = [
            ("1", "Управление сотрудниками", "employees"),
            ("2", "Поиск сотрудников", "search"),
            ("3", "Управление согласиями", "consents"),
            ("4", "Журнал аудита", "audit"),
            ("5", "Статистика системы", "stats")
        ]

        if self._service._permissions.get('can_manage_users'):
            menu_items.append(("6", "Управление пользователями", "users"))

        menu_items.extend([
            ("0", "Выход из системы", "exit")
        ])

        for num, name, _ in menu_items:
            print(f"  {num}. {name}")

        choice = input("\nВыберите действие: ").strip()

        for num, _, key in menu_items:
            if choice == num:
                return key

        return ""

    def _menu_employees(self):
        """Меню управления сотрудниками"""
        while True:
            self._print_header("УПРАВЛЕНИЕ СОТРУДНИКАМИ")

            print("1. Просмотр списка сотрудников")
            print("2. Просмотр карточки сотрудника")

            if self._service._permissions.get('can_create_employee'):
                print("3. Добавить нового сотрудника")
            if self._service._permissions.get('can_edit_employee'):
                print("4. Редактировать сотрудника")
            if self._service._permissions.get('can_delete_employee'):
                print("5. Уволить сотрудника")
            if self._service._permissions.get('can_block_employee'):
                print("6. Заблокировать сотрудника")
                print("7. Разблокировать сотрудника")
            if self._service._permissions.get('can_hard_delete'):
                print("8. Полное удаление сотрудника (Security Only)")

            print("0. Назад")

            choice = input("\nВыберите действие: ").strip()

            if choice == '0':
                break
            elif choice == '1':
                self._show_employee_list()
            elif choice == '2':
                self._show_employee_card()
            elif choice == '3' and self._service._permissions.get('can_create_employee'):
                self._create_employee()
            elif choice == '4' and self._service._permissions.get('can_edit_employee'):
                self._edit_employee()
            elif choice == '5' and self._service._permissions.get('can_delete_employee'):
                self._fire_employee()
            elif choice == '6' and self._service._permissions.get('can_block_employee'):
                self._block_employee()
            elif choice == '7' and self._service._permissions.get('can_block_employee'):
                self._unblock_employee()
            elif choice == '8' and self._service._permissions.get('can_hard_delete'):
                self._hard_delete_employee()

    def _show_employee_list(self):
        """Показать список сотрудников"""
        self._print_header("СПИСОК СОТРУДНИКОВ")

        success, msg, employees = self._service.get_all_employees()

        if not success:
            print(f"\n[ОШИБКА] {msg}")
        else:
            print(f"\n{msg}")
            print("-" * 70)
            print(f"{'ID':<5} {'ФИО':<30} {'Должность':<20} {'Статус':<15}")
            print("-" * 70)
            for emp in employees:
                print(f"{emp['id']:<5} {emp['full_name']:<30} {emp['position']:<20} {emp['status']:<15}")
            print("-" * 70)

        input("\nНажмите Enter для продолжения...")

    def _show_employee_card(self):
        """Показать карточку сотрудника"""
        self._print_header("КАРТОЧКА СОТРУДНИКА")

        try:
            emp_id = int(input("Введите ID сотрудника: "))
        except ValueError:
            print("[ОШИБКА] Неверный ID")
            input("\nНажмите Enter...")
            return

        include_sensitive = False
        if self._service._permissions.get('can_view_sensitive_data'):
            resp = input("Показать персональные данные? (y/n): ").strip().lower()
            include_sensitive = resp == 'y'

        success, msg, data = self._service.get_employee(emp_id, include_sensitive)

        if not success:
            print(f"\n[ОШИБКА] {msg}")
        else:
            print("\n" + "=" * 50)
            for key, value in data.items():
                print(f"  {key}: {value}")
            print("=" * 50)

        input("\nНажмите Enter для продолжения...")

    def _create_employee(self):
        """Создать нового сотрудника"""
        self._print_header("ДОБАВЛЕНИЕ СОТРУДНИКА")

        data = {}
        data['full_name'] = input("ФИО: ").strip()
        data['position'] = input("Должность: ").strip()
        data['department'] = input("Отдел: ").strip()
        data['email'] = input("Email: ").strip()
        data['phone'] = input("Телефон (10 цифр): ").strip()

        print("\nПерсональные данные (необязательно):")
        passport = input("Паспорт (серия номер): ").strip()
        if passport:
            data['passport'] = passport
        snils = input("СНИЛС: ").strip()
        if snils:
            data['snils'] = snils

        success, msg, emp = self._service.create_employee(data)

        if success:
            print(f"\n[УСПЕХ] {msg}")
        else:
            print(f"\n[ОШИБКА] {msg}")

        input("\nНажмите Enter для продолжения...")

    def _edit_employee(self):
        """Редактировать сотрудника"""
        self._print_header("РЕДАКТИРОВАНИЕ СОТРУДНИКА")

        try:
            emp_id = int(input("Введите ID сотрудника: "))
        except ValueError:
            print("[ОШИБКА] Неверный ID")
            input("\nНажмите Enter...")
            return

        print("\nВведите новые значения (оставьте пустым, чтобы не менять):")
        data = {}

        full_name = input("ФИО: ").strip()
        if full_name:
            data['full_name'] = full_name

        position = input("Должность: ").strip()
        if position:
            data['position'] = position

        email = input("Email: ").strip()
        if email:
            data['email'] = email

        phone = input("Телефон: ").strip()
        if phone:
            data['phone'] = phone

        if data:
            success, msg = self._service.update_employee(emp_id, data)
            print(f"\n[{'УСПЕХ' if success else 'ОШИБКА'}] {msg}")
        else:
            print("\n[INFO] Нет данных для обновления")

        input("\nНажмите Enter для продолжения...")

    def _fire_employee(self):
        """Уволить сотрудника"""
        self._print_header("УВОЛЬНЕНИЕ СОТРУДНИКА")

        try:
            emp_id = int(input("Введите ID сотрудника: "))
        except ValueError:
            print("[ОШИБКА] Неверный ID")
            input("\nНажмите Enter...")
            return

        confirm = input(f"Вы уверены, что хотите уволить сотрудника #{emp_id}? (y/n): ").strip().lower()

        if confirm == 'y':
            success, msg = self._service.delete_employee(emp_id, hard_delete=False)
            print(f"\n[{'УСПЕХ' if success else 'ОШИБКА'}] {msg}")

        input("\nНажмите Enter для продолжения...")

    def _block_employee(self):
        """Заблокировать сотрудника"""
        self._print_header("БЛОКИРОВКА СОТРУДНИКА")

        try:
            emp_id = int(input("Введите ID сотрудника: "))
        except ValueError:
            print("[ОШИБКА] Неверный ID")
            input("\nНажмите Enter...")
            return

        reason = input("Причина блокировки: ").strip()

        if reason:
            success, msg = self._service.block_employee(emp_id, reason)
            print(f"\n[{'УСПЕХ' if success else 'ОШИБКА'}] {msg}")
        else:
            print("\n[ОШИБКА] Необходимо указать причину блокировки")

        input("\nНажмите Enter для продолжения...")

    def _unblock_employee(self):
        """Разблокировать сотрудника"""
        self._print_header("РАЗБЛОКИРОВКА СОТРУДНИКА")

        try:
            emp_id = int(input("Введите ID сотрудника: "))
        except ValueError:
            print("[ОШИБКА] Неверный ID")
            input("\nНажмите Enter...")
            return

        success, msg = self._service.unblock_employee(emp_id)
        print(f"\n[{'УСПЕХ' if success else 'ОШИБКА'}] {msg}")

        input("\nНажмите Enter для продолжения...")

    def _hard_delete_employee(self):
        """Полное удаление сотрудника (только Security Officer)"""
        self._print_header("ПОЛНОЕ УДАЛЕНИЕ СОТРУДНИКА")
        print("[ВНИМАНИЕ] Это действие необратимо!")

        try:
            emp_id = int(input("Введите ID сотрудника: "))
        except ValueError:
            print("[ОШИБКА] Неверный ID")
            input("\nНажмите Enter...")
            return

        confirm1 = input(f"Вы уверены? (y/n): ").strip().lower()
        if confirm1 == 'y':
            confirm2 = input(f"ТОЧНО уверены? Данные будут безвозвратно удалены! (yes/no): ").strip().lower()
            if confirm2 == 'yes':
                success, msg = self._service.delete_employee(emp_id, hard_delete=True)
                print(f"\n[{'УСПЕХ' if success else 'ОШИБКА'}] {msg}")

        input("\nНажмите Enter для продолжения...")

    def _menu_search(self):
        """Меню поиска"""
        self._print_header("ПОИСК СОТРУДНИКОВ")

        query = input("Введите имя, email или должность: ").strip()

        if query:
            success, msg, results = self._service.search_employees(query)

            if success and results:
                print(f"\n{msg}")
                print("-" * 70)
                print(f"{'ID':<5} {'ФИО':<30} {'Должность':<20} {'Отдел':<15}")
                print("-" * 70)
                for emp in results:
                    print(f"{emp['id']:<5} {emp['full_name']:<30} {emp['position']:<20} {emp['department']:<15}")
                print("-" * 70)
            else:
                print(f"\n[INFO] {msg}")
        else:
            print("\n[INFO] Пустой запрос")

        input("\nНажмите Enter для продолжения...")

    def _menu_consents(self):
        """Меню управления согласиями"""
        while True:
            self._print_header("УПРАВЛЕНИЕ СОГЛАСИЯМИ")

            print("1. Просмотр согласий сотрудника")

            if self._service._permissions.get('can_manage_consents'):
                print("2. Предоставить согласие")
                print("3. Отозвать согласие")

            print("0. Назад")

            choice = input("\nВыберите действие: ").strip()

            if choice == '0':
                break
            elif choice == '1':
                self._show_employee_consents()
            elif choice == '2' and self._service._permissions.get('can_manage_consents'):
                self._grant_consent()
            elif choice == '3' and self._service._permissions.get('can_manage_consents'):
                self._revoke_consent()

    def _show_employee_consents(self):
        """Показать согласия сотрудника"""
        try:
            emp_id = int(input("Введите ID сотрудника: "))
        except ValueError:
            print("[ОШИБКА] Неверный ID")
            input("\nНажмите Enter...")
            return

        success, msg, consents = self._service.get_employee_consents(emp_id)

        if success:
            print(f"\n{msg}")
            print("-" * 80)
            print(f"{'ID':<5} {'Тип':<15} {'Дата выдачи':<12} {'Действует до':<12} {'Статус':<15}")
            print("-" * 80)
            for c in consents:
                print(f"{c['id']:<5} {c['type']:<15} {c['granted_date']:<12} {c['valid_until']:<12} {c['status']:<15}")
            print("-" * 80)
        else:
            print(f"\n[ОШИБКА] {msg}")

        input("\nНажмите Enter для продолжения...")

    def _grant_consent(self):
        """Предоставить согласие"""
        self._print_header("ПРЕДОСТАВЛЕНИЕ СОГЛАСИЯ")

        try:
            emp_id = int(input("Введите ID сотрудника: "))
        except ValueError:
            print("[ОШИБКА] Неверный ID")
            input("\nНажмите Enter...")
            return

        print("\nТипы согласий:")
        print("1. processing - обработка ПДн")
        print("2. transfer - передача ПДн третьим лицам")
        print("3. biometric - обработка биометрических данных")

        consent_types = {'1': 'processing', '2': 'transfer', '3': 'biometric'}
        type_choice = input("Выберите тип (1-3): ").strip()

        if type_choice not in consent_types:
            print("[ОШИБКА] Неверный выбор")
            input("\nНажмите Enter...")
            return

        try:
            days = int(input("Срок действия (дней, по умолчанию 365): ") or "365")
        except ValueError:
            days = 365

        success, msg = self._service.grant_consent(emp_id, consent_types[type_choice], days)
        print(f"\n[{'УСПЕХ' if success else 'ОШИБКА'}] {msg}")

        input("\nНажмите Enter для продолжения...")

    def _revoke_consent(self):
        """Отозвать согласие"""
        try:
            consent_id = int(input("Введите ID согласия: "))
        except ValueError:
            print("[ОШИБКА] Неверный ID")
            input("\nНажмите Enter...")
            return

        confirm = input(f"Отозвать согласие #{consent_id}? (y/n): ").strip().lower()

        if confirm == 'y':
            success, msg = self._service.revoke_consent(consent_id)
            print(f"\n[{'УСПЕХ' if success else 'ОШИБКА'}] {msg}")

        input("\nНажмите Enter для продолжения...")

    def _menu_audit(self):
        """Меню журнала аудита"""
        self._print_header("ЖУРНАЛ АУДИТА")

        print("1. Все записи")
        print("2. Мои действия")
        print("3. Только инциденты безопасности")

        choice = input("\nВыберите фильтр: ").strip()

        filter_map = {'1': 'all', '2': 'my', '3': 'security'}
        filter_type = filter_map.get(choice, 'all')

        success, msg, logs = self._service.get_audit_logs(filter_type)

        if success and logs:
            print(f"\n{msg}")
            print("-" * 90)
            print(f"{'Дата/время':<20} {'Пользователь':<12} {'Действие':<25} {'Объект':<12} {'Результат':<10}")
            print("-" * 90)
            for log in logs:
                print(
                    f"{log['timestamp']:<20} {log['user']:<12} {log['action']:<25} {log['target']:<12} {log['result']:<10}")
            print("-" * 90)
        else:
            print(f"\n[INFO] {msg}")

        input("\nНажмите Enter для продолжения...")

    def _menu_stats(self):
        """Показать статистику"""
        self._print_header("СТАТИСТИКА СИСТЕМЫ")

        success, msg, stats = self._service.get_statistics()

        if success:
            print(f"\n{msg}")
            print("-" * 40)
            print(f"  Всего сотрудников:      {stats['total_employees']}")
            print(f"  Активных сотрудников:   {stats['active_employees']}")
            print(f"  Заблокированных:        {stats['blocked_employees']}")
            print(f"  Уволенных:              {stats['fired_employees']}")
            print(f"  Всего согласий:         {stats['total_consents']}")
            print(f"  Истекших согласий:      {stats['expired_consents']}")
            print(f"  Пользователей системы:  {stats['active_users']}")
            print(f"  Записей аудита:         {stats['total_audit_records']}")
            print(f"  Инцидентов сегодня:     {stats['security_alerts_today']}")
            print("-" * 40)

        input("\nНажмите Enter для продолжения...")

    def _menu_users(self):
        """Меню управления пользователями"""
        while True:
            self._print_header("УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ")

            print("1. Просмотр списка пользователей")
            print("2. Создать нового пользователя")
            print("3. Заблокировать пользователя")
            print("0. Назад")

            choice = input("\nВыберите действие: ").strip()

            if choice == '0':
                break
            elif choice == '1':
                self._show_users_list()
            elif choice == '2':
                self._create_user()
            elif choice == '3':
                self._block_user()

    def _show_users_list(self):
        """Показать список пользователей"""
        self._print_header("ПОЛЬЗОВАТЕЛИ СИСТЕМЫ")

        success, msg, users = self._service.get_all_users()

        if success:
            print(f"\n{msg}")
            print("-" * 80)
            print(f"{'ID':<5} {'Логин':<15} {'ФИО':<25} {'Роль':<20} {'Активен':<8}")
            print("-" * 80)
            for u in users:
                print(
                    f"{u['id']:<5} {u['username']:<15} {u['full_name']:<25} {u['role']:<20} {'Да' if u['is_active'] else 'Нет':<8}")
            print("-" * 80)

        input("\nНажмите Enter для продолжения...")

    def _create_user(self):
        """Создать пользователя"""
        self._print_header("СОЗДАНИЕ ПОЛЬЗОВАТЕЛЯ")

        username = input("Логин: ").strip()
        password = input("Пароль: ").strip()
        full_name = input("ФИО: ").strip()
        department = input("Отдел: ").strip()

        print("\nДоступные роли:")
        print("1. HR_Admin")
        print("2. Security_Officer")
        print("3. Data_Protection_Officer")
        print("4. Manager")

        role_map = {'1': 'HR_Admin', '2': 'Security_Officer',
                    '3': 'Data_Protection_Officer', '4': 'Manager'}
        role_choice = input("Выберите роль (1-4): ").strip()
        role = role_map.get(role_choice, 'Manager')

        if username and password and full_name:
            success, msg, _ = self._service.create_user(username, password, full_name, role, department)
            print(f"\n[{'УСПЕХ' if success else 'ОШИБКА'}] {msg}")
        else:
            print("\n[ОШИБКА] Все поля обязательны")

        input("\nНажмите Enter для продолжения...")

    def _block_user(self):
        """Заблокировать пользователя"""
        try:
            user_id = int(input("Введите ID пользователя: "))
        except ValueError:
            print("[ОШИБКА] Неверный ID")
            input("\nНажмите Enter...")
            return

        confirm = input(f"Заблокировать пользователя #{user_id}? (y/n): ").strip().lower()

        if confirm == 'y':
            success, msg = self._service.block_user(user_id)
            print(f"\n[{'УСПЕХ' if success else 'ОШИБКА'}] {msg}")

        input("\nНажмите Enter для продолжения...")

    def run(self):
        """Запуск приложения"""
        self._print_security_banner()
        self._init_repositories()

        if not self._login():
            print("[INFO] Завершение работы")
            return

        # Основной цикл
        while True:
            action = self._show_main_menu()

            if action == "exit":
                # Аудит выхода
                self._audit_repo.add_entry(AuditLogEntry(
                    user=self._current_user.username,
                    user_role=self._current_user.role,
                    action=AuditAction.USER_LOGOUT,
                    target_type="User",
                    target_id=self._current_user.id
                ))
                self._print_header("ЗАВЕРШЕНИЕ РАБОТЫ")
                print(f"\n[INFO] Пользователь {self._current_user.full_name} вышел из системы")
                break
            elif action == "employees":
                self._menu_employees()
            elif action == "search":
                self._menu_search()
            elif action == "consents":
                self._menu_consents()
            elif action == "audit":
                self._menu_audit()
            elif action == "stats":
                self._menu_stats()
            elif action == "users":
                self._menu_users()

if __name__ == "__main__":
    ui = ConsoleUI()
    ui.run()