from fastapi import FastAPI, Response,  Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from . import models, schemas, crud, auth
from .database import engine, get_db
from sqlalchemy.orm import Session
from typing import List

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

@app.post("/auth/register")
async def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_username(db, user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    return crud.create_user(db, user)


@app.post("/auth/login")
async def login(
        response: Response,
        form_data: OAuth2PasswordRequestForm = Depends(),
        db: Session = Depends(get_db)
):
    user = crud.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
        )
    access_token = auth.create_access_token(
        data={"sub": user.username}
    )
    response.set_cookie(key="user_id",value=str(user.id))
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/change-password")
async def change_password(
        password_data: schemas.ChangePasswordRequest,
        db: Session = Depends(get_db)
):
    try:
        crud.change_password(
            db=db,
            username=password_data.username,
            current_password=password_data.current_password,
            new_password=password_data.new_password
        )
        return {"message": "Пароль успешно изменен"}
    except ValueError as e:
        raise HTTPException(
            status_code=404,
            detail=str(e)
        )

@app.post("/create-task")
async def create_task(task: schemas.TaskCreate, db: Session = Depends(get_db), creator_id = Depends(crud.get_user_id_from_cookie)):
    return crud.create_task(db, task, creator_id)

@app.post("/manager/change-login")
async def change_login(data: schemas.UserUpdateUsername,
                       db: Session = Depends(get_db),
                       user_id: int = Depends(crud.get_user_id_from_cookie)):
    return crud.change_login_by_manager(db, data, user_id)

@app.post("/manager/change-role")
async def change_role(data: schemas.UserUpdateRole,
                       db: Session = Depends(get_db),
                       user_id: int = Depends(crud.get_user_id_from_cookie)):
    return crud.change_role_by_manager(db, data, user_id)

@app.post("/manager/delete-task")
async def change_role(task_id: int,
                      db: Session = Depends(get_db),
                      user_id: int = Depends(crud.get_user_id_from_cookie)):
    return crud.delete_task(db, task_id, user_id)

@app.post("/tasks/update")
async def update_task(task:schemas.TaskUpdateStatus, db: Session = Depends(get_db)):
    return crud.change_task_status(db, task)

@app.get("/tasks/all-tasks", response_model=List[schemas.Task])
def read_tasks(db: Session = Depends(get_db)):
    tasks = crud.get_all_tasks(db)
    return tasks

@app.post("/tasks/search")
async def search_tasks(search: schemas.TaskSearch, db: Session = Depends(get_db)):
    return crud.search_task(db, search)