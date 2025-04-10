from fastapi import status


def test_health_check(client):
    """Тест эндпоинта /health"""
    response = client.get('/health')
    assert response.status_code == status.HTTP_200_OK


def test_get_all_tasks(client, db_session):
    user_data = {
        "username": "testuser",
        "password": "testpass"
    }
    client.post("/auth/register", json=user_data)
    login_response = client.post("/auth/login", data={
        "username": user_data["username"],
        "password": user_data["password"]
    })
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    task_data_1 = {
        "type": "bug",
        "title": "Test Task 1",
        "description": "This is test task 1",
        "priority": "high",
        "assignee_id": 0,
        "blocks": [],
        "blocked_by": []
    }

    task_data_2 = {
        "type": "task",
        "title": "Test Task 2",
        "description": "This is test task 2",
        "priority": "medium",
        "assignee_id": 0,
        "blocks": [],
        "blocked_by": []
    }

    response_1 = client.post("/create-task", json=task_data_1, headers=headers)
    response_2 = client.post("/create-task", json=task_data_2, headers=headers)

    assert response_1.status_code == status.HTTP_200_OK
    assert response_2.status_code == status.HTTP_200_OK

    response = client.get("/tasks/all-tasks", headers=headers)
    assert response.status_code == status.HTTP_200_OK

    tasks = response.json()
    print("Полученные задачи:", tasks)

    assert isinstance(tasks, list)
    assert len(tasks) >= 2

    task_titles = {task["title"] for task in tasks}
    assert "Test Task 1" in task_titles
    assert "Test Task 2" in task_titles

def test_register_user(client, db_session):
    user_data = {"username": "newuser", "password": "newpassword"}
    response = client.post("/auth/register", json=user_data)
    assert response.status_code == status.HTTP_200_OK
    assert "id" in response.json()


def test_login_user(client, db_session):
    user_data = {"username": "testuser", "password": "testpassword"}
    client.post("/auth/register", json=user_data)

    login_data = {"username": user_data["username"], "password": user_data["password"]}
    for content_type in [{"data": login_data}, {"json": login_data}]:
        response = client.post("/auth/login", **content_type)
        if response.status_code == 200:
            token = response.json().get("access_token") or response.json().get("token")
            if token:
                break

    assert response.status_code == status.HTTP_200_OK
    assert token is not None


def test_change_password(client, db_session):
    user_data = {"username": "testuser", "password": "testpassword"}
    client.post("/auth/register", json=user_data)

    login_data = {"username": user_data["username"], "password": user_data["password"]}
    login_response = client.post("/auth/login", data=login_data)
    auth_token = login_response.json().get("access_token") or login_response.json().get("token")

    change_password_data = {
        "username": user_data["username"],
        "current_password": user_data["password"],
        "new_password": "newpassword123"
    }
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.post("/change-password", json=change_password_data, headers=headers)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["message"] == "Пароль успешно изменен"


def test_create_task(client, db_session):
    user_data = {"username": "testuser", "password": "testpassword"}
    client.post("/auth/register", json=user_data)

    login_data = {"username": user_data["username"], "password": user_data["password"]}
    login_response = client.post("/auth/login", data=login_data)
    auth_token = login_response.json().get("access_token") or login_response.json().get("token")

    task_data = {
        "type": "bug",
        "title": "Test Task",
        "description": "This is a test task",
        "priority": "high",
        "assignee_id": None,
        "blocks": [],
        "blocked_by": []
    }
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.post("/create-task", json=task_data, headers=headers)

    assert response.status_code == status.HTTP_200_OK
    assert "id" in response.json()


def test_update_task_status(client, db_session):
    user_data = {"username": "testuser", "password": "testpassword"}
    client.post("/auth/register", json=user_data)

    login_data = {"username": user_data["username"], "password": user_data["password"]}
    login_response = client.post("/auth/login", data=login_data)
    auth_token = login_response.json().get("access_token")

    task_data = {
        "type": "bug",
        "title": "Test Task",
        "description": "This is a test task",
        "priority": "high",
        "assignee_id": 0,
        "blocks": [],
        "blocked_by": []
    }
    headers = {"Authorization": f"Bearer {auth_token}"}
    create_response = client.post("/create-task", json=task_data, headers=headers)
    task_id = create_response.json()["id"]

    update_data = {
        "task_id": task_id,
        "new_status": "In progress",
        "new_assignee_id": 1
    }
    update_response = client.post("/tasks/update", json=update_data, headers=headers)

    assert update_response.status_code == status.HTTP_200_OK
    assert update_response.json()["status"] == "In progress"


def test_search_tasks(client, db_session):
    user_data = {"username": "testuser", "password": "testpassword"}
    client.post("/auth/register", json=user_data)

    login_data = {"username": user_data["username"], "password": user_data["password"]}
    login_response = client.post("/auth/login", data=login_data)
    auth_token = login_response.json().get("access_token") or login_response.json().get("token")

    search_data = {"query": "Test Task", "limit": 10, "offset": 0}
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.post("/tasks/search", json=search_data, headers=headers)

    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), list)


def test_manager_change_login(client, db_session):
    regular_user_data = {"username": "regular_user", "password": "regular_pass"}
    regular_user_response = client.post("/auth/register", json=regular_user_data)
    regular_user_id = regular_user_response.json()["id"]

    manager_data = {"username": "manager_user", "password": "manager_pass"}
    manager_response = client.post("/auth/register", json=manager_data)
    manager_id = manager_response.json()["id"]

    from app.models import User
    manager_user = db_session.query(User).filter_by(id=manager_id).first()
    manager_user.role = "manager"
    db_session.commit()

    login_data = {"username": manager_data["username"], "password": manager_data["password"]}
    login_response = client.post("/auth/login", data=login_data)
    auth_token = login_response.json().get("access_token")

    change_login_data = {
        "id": regular_user_id,
        "new_username": "new_regular_username"
    }
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.post("/manager/change-login", json=change_login_data, headers=headers)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["username"] == "new_regular_username"


def test_manager_change_role(client, db_session):
    regular_user_data = {"username": "regular_user2", "password": "regular_pass2"}
    regular_user_response = client.post("/auth/register", json=regular_user_data)
    regular_user_id = regular_user_response.json()["id"]


    manager_data = {"username": "manager_user2", "password": "manager_pass2"}
    manager_response = client.post("/auth/register", json=manager_data)
    manager_id = manager_response.json()["id"]

    from app.models import User
    manager_user = db_session.query(User).filter_by(id=manager_id).first()
    manager_user.role = "manager"
    db_session.commit()

    login_data = {"username": manager_data["username"], "password": manager_data["password"]}
    login_response = client.post("/auth/login", data=login_data)
    auth_token = login_response.json().get("access_token")

    change_role_data = {
        "id": regular_user_id,
        "new_role": "tester"
    }
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.post("/manager/change-role", json=change_role_data, headers=headers)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["role"] == "tester"


def test_manager_delete_task(client, db_session):
    manager_data = {"username": "manager_user3", "password": "manager_pass3"}
    manager_response = client.post("/auth/register", json=manager_data)
    manager_id = manager_response.json()["id"]

    from app.models import User
    manager_user = db_session.query(User).filter_by(id=manager_id).first()
    manager_user.role = "manager"
    db_session.commit()

    login_data = {"username": manager_data["username"], "password": manager_data["password"]}
    login_response = client.post("/auth/login", data=login_data)
    auth_token = login_response.json().get("access_token")
    headers = {"Authorization": f"Bearer {auth_token}"}

    task_data = {
        "type": "bug",
        "title": "Task to delete",
        "description": "This task will be deleted",
        "priority": "high",
        "assignee_id": 0,
        "blocks": [],
        "blocked_by": []
    }
    create_response = client.post("/create-task", json=task_data, headers=headers)
    task_id = create_response.json()["id"]

    response = client.post(
        "/manager/delete-task?task_id={}".format(task_id),
        headers=headers
    )

    assert response.status_code == status.HTTP_200_OK

    check_response = client.get(f"/tasks/{task_id}", headers=headers)
    assert check_response.status_code == status.HTTP_404_NOT_FOUND