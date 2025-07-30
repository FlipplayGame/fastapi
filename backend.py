from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

# Разрешаем CORS для фронта (чтобы React мог подключаться)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # В продакшене замени на конкретный домен фронта
    allow_methods=["*"],
    allow_headers=["*"],
)

# "База данных" в памяти (для примера)
fake_db = {
    "claimedTasks": {
        "task1": False,
        "task2": False,
        "task3": False,
    }
}

fake_player_info = {
    "PlayerInfo": {
        "nickname": "Emelya",
        "balance": 5000,
    }
}



# Модель для запроса на обновление задачи
class ClaimRequest(BaseModel):
    taskId: str


class BalanceUpdate(BaseModel):
    nickname: str
    amount: int


@app.get("/tasks")
def get_tasks():
    """Отдаёт текущее состояние всех задач."""
    return fake_db["claimedTasks"]

@app.get("/player")
def get_player_info():
    return fake_player_info["PlayerInfo"]


@app.post("/player/update-balance")
def update_balance(data: BalanceUpdate):
    print(data)
    fake_player_info["PlayerInfo"]["balance"] = fake_player_info["PlayerInfo"]["balance"] - data.amount


@app.post("/claim")
def claim_task(request: ClaimRequest):
    print("ПОлучили запрос")
    """Обновляет статус задачи на 'Claimed'."""
    if request.taskId not in fake_db["claimedTasks"]:
        raise HTTPException(status_code=404, detail="Task not found")
    
    fake_db["claimedTasks"][request.taskId] = True
    return {"message": f"Task {request.taskId} claimed!", "claimedTasks": fake_db["claimedTasks"]}
