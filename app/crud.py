from sqlalchemy.orm import Session
from sqlalchemy import or_
from fastapi import Cookie, HTTPException, status
from app import models, schemas
from passlib.context import CryptContext
from datetime import datetime

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password: str):
    return pwd_context.hash(password)


def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()


def get_user_role(db: Session, user_id: int):
    user = get_user(db, user_id)
    return user.role


def get_user_id_from_cookie(user_id: str = Cookie(None)) -> int:
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Требуется аутентификация"
        )
    return int(user_id)


def get_user_by_username(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()

def get_task_by_id(db: Session, task_id: int):
    return db.query(models.Task).filter(models.Task.id == task_id).first()


def change_password(db: Session, username: str, current_password: str, new_password: str):
    user = get_user_by_username(db, username)
    if not pwd_context.verify(current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Неверный текущий пароль"
        )
    user.password_hash = get_password_hash(new_password)
    db.commit()
    db.refresh(user)
    return user


def create_user(db: Session, user: schemas.UserCreate):
    hashed_password = get_password_hash(user.password)
    db_user = models.User(username=user.username, password_hash=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def create_task(db: Session, task_data: schemas.TaskCreate, creator_id: int):
    if task_data.assignee_id == 0:
        task_data.assignee_id = None
    assignee = None
    if task_data.assignee_id:
        assignee = db.query(models.User).get(task_data.assignee_id)
        if not assignee:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Исполнитель не найден"
                )
        if get_user_role(db, task_data.assignee_id) == "manager":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Менеджер не может быть исполнителем задачи"
            )
    task_dict = task_data.model_dump(exclude={"blocks", "blocked_by"})
    task_dict["creator_id"] = creator_id
    db_task = models.Task(**task_dict)
    db.add(db_task)
    db.commit()

    if task_data.blocks:
        for blocking_id in task_data.blocks:
            if blocking_id == db_task.id:
                continue
            if not db.query(models.Task).get(blocking_id):
                continue
            db_dep = models.TaskDependency(
                blocking_id=db_task.id,
                blocked_id=blocking_id
            )
            db.add(db_dep)

    if task_data.blocked_by:
        for blocked_id in task_data.blocked_by:
            if blocked_id == db_task.id:
                continue
            if not db.query(models.Task).get(blocked_id):
                continue
            db_dep = models.TaskDependency(
                blocking_id=blocked_id,
                blocked_id=db_task.id
            )
            db.add(db_dep)

    db.commit()
    db.refresh(db_task)
    return db_task

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(db: Session, username: str, password: str):
    user = get_user_by_username(db, username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверное имя пользователя или пароль"
        )
    if not verify_password(password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверное имя пользователя или пароль"
        )
    return user

def check_manager(db: Session, user_id: int):
    role = get_user_role(db, user_id)
    if role != "manager":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Доступ запрещен. Вы не менеджер"
        )
    else:
        return True

def change_login_by_manager(db: Session, data:schemas.UserUpdateUsername, user_id: int):
    if check_manager(db, user_id):
        user = db.query(models.User).filter(models.User.id == data.id).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="Пользователь не найден")
        new_username_check = get_user_by_username(db, data.new_username)
        if new_username_check:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Имя пользователя занято")
        user.username = data.new_username
        db.commit()
        db.refresh(user)

        return user
def change_role_by_manager(db: Session, data:schemas.UserUpdateRole, user_id: int):
    if check_manager(db, user_id):
        user = db.query(models.User).filter(models.User.id == data.id).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="Пользователь не найден")
        if not get_user(db, data.id):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Пользователь не найден")

        user.role = data.new_role
        db.commit()
        db.refresh(user)
        return user

def delete_task(db: Session, task_id: int, user_id: int):
    if check_manager(db, user_id):
        task = task = db.query(models.Task).filter(models.Task.id == task_id).first()
        if not task:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="Запись не найдена")
        db_task = db.query(models.Task).filter(models.Task.id == task_id).first()
        db.delete(db_task)
        db.commit()
        return task

def get_all_tasks(db: Session):
    return db.query(models.Task).all()

def change_task_status(db: Session, data: schemas.TaskUpdateStatus):
    ALL_STATUSES = ["To do", "In progress", "Code review", "Dev test", "Testing", "Done", "Wontfix"]
    DONE_STATUS = "Done"
    WONTFIX_STATUS = "Wontfix"
    TODO_STATUS = "To do"

    task = get_task_by_id(db, data.task_id)
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Задача не найдена")

    current_status = task.status
    new_status = data.new_status

    current_index = ALL_STATUSES.index(current_status)
    new_index = ALL_STATUSES.index(new_status)

    if not (current_status == TODO_STATUS and new_status == WONTFIX_STATUS):
        if new_index != current_index + 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Недопустимый переход между статусами. Допустим только переход на следующий статус."
            )

    if new_status not in [DONE_STATUS, WONTFIX_STATUS]:
        blocking_tasks = (
            db.query(models.Task)
            .join(models.TaskDependency, models.TaskDependency.blocking_id == models.Task.id)
            .filter(models.TaskDependency.blocked_id == data.task_id)
            .all()
        )

        if blocking_tasks:
            not_done_blockers = [t for t in blocking_tasks if t.status not in [DONE_STATUS, WONTFIX_STATUS]]
            if not_done_blockers:
                blocker_ids = [t.id for t in not_done_blockers]
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Задача заблокирована задачами: {', '.join(map(str, blocker_ids))}"
                )

    new_assignee_role = get_user_role(db, data.new_assignee_id) if data.new_assignee_id != 0 else None

    if new_assignee_role == "manager":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Менеджер не может быть назначен исполнителем задачи"
        )

    if new_status in [WONTFIX_STATUS, DONE_STATUS]:
        db.query(models.TaskDependency) \
            .filter(models.TaskDependency.blocking_id == data.task_id) \
            .delete()

        task.status = new_status
        task.updated_at = datetime.now()

        if new_status == WONTFIX_STATUS and data.new_assignee_id != 0 and new_assignee_role != "team_lead":
            task.assignee_id = data.new_assignee_id

        db.commit()
        return task

    if new_status == "In progress":
        if new_assignee_role == "tester":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Тестировщик не может быть исполнителем для статуса In progress"
            )
        if data.new_assignee_id == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Для статуса In progress должен быть указан исполнитель"
            )
        task.assignee_id = data.new_assignee_id

    elif new_status in ["Code review", "Dev test"]:
        if new_assignee_role == "tester":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Тестировщик не может быть исполнителем для этого статуса"
            )
        if data.new_assignee_id != 0:
            task.assignee_id = data.new_assignee_id

    elif new_status == "Testing":
        if new_assignee_role == "developer":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Разработчик не может быть исполнителем для статуса Testing"
            )
        if data.new_assignee_id != 0:
            task.assignee_id = data.new_assignee_id


    task.status = new_status
    task.updated_at = datetime.now()
    db.commit()
    db.refresh(task)
    return task

def search_task (db: Session, search: schemas.TaskSearch):
    query = db.query(models.Task)
    if search.query:
        try:
            task_id = int(search.query)
            query = query.filter(models.Task.id == task_id)
        except ValueError:
            search_pattern = f"%{search.query}%"
            query = query.filter(
                or_(
                    models.Task.title.ilike(search_pattern),
                    models.Task.description.ilike(search_pattern)
                )
            )
    query = query.order_by(models.Task.updated_at.desc())
    tasks = query.offset(search.offset).limit(search.limit).all()

    return tasks