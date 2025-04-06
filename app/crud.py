from sqlalchemy.orm import Session
from fastapi import Cookie, HTTPException, status
from . import models, schemas
from passlib.context import CryptContext

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


def get_task(db: Session, task_id: int):
    task = db.query(models.Task).filter(models.Task.id == task_id).first()
    if task:
        return schemas.Task.model_validate(task)
    return None

def get_tasks(db: Session, skip: int, limit: int):
    return db.query(models.Task).offset(skip).limit(limit).all()


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