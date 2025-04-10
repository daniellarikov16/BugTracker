import pytest
from fastapi import status


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