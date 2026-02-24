import math
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy import Boolean, DateTime, Float, Integer, String, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

app = FastAPI(
    title="Calculadora API",
    description="API de calculadora com autenticação JWT, PostgreSQL e dashboard",
    version="2.0.0",
)

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/calculadora")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-this-secret-in-production")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
REFRESH_TTL_SECONDS = REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
redis_client = Redis.from_url(REDIS_URL, decode_responses=True)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


class OperacaoRequest(BaseModel):
    numero1: float
    numero2: float


class OperacaoUnariaRequest(BaseModel):
    numero: float


class OperacaoAvancadaRequest(BaseModel):
    numero: float
    potencia: Optional[float] = None


class RegraDeTresRequest(BaseModel):
    valor_a: float
    valor_b: float
    valor_c: float


class ListaNumerosRequest(BaseModel):
    numeros: list[float]


class MediaPonderadaRequest(BaseModel):
    valores: list[float]
    pesos: list[float]


class VariacaoPercentualRequest(BaseModel):
    valor_inicial: float
    valor_final: float


class JurosRequest(BaseModel):
    capital: float
    taxa: float
    tempo: float


class InteiroRequest(BaseModel):
    numero: int


class InteirosRequest(BaseModel):
    numero1: int
    numero2: int


class EquacaoSegundoGrauRequest(BaseModel):
    a: float
    b: float
    c: float


class EquacaoSegundoGrauResponse(BaseModel):
    delta: float
    raizes: list[str]
    operacao: str


class ImcRequest(BaseModel):
    peso: float
    altura: float


class ResultadoResponse(BaseModel):
    resultado: float
    operacao: str


class UserRegisterRequest(BaseModel):
    username: str
    email: str
    password: str


class UserLoginRequest(BaseModel):
    username: str
    password: str


class TokenRefreshRequest(BaseModel):
    refresh_token: str


class AuthTokensResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class MessageResponse(BaseModel):
    message: str


class DashboardResponse(BaseModel):
    usuario: str
    email: str
    total_usuarios: int
    total_refresh_tokens_ativos: int
    total_operacoes_disponiveis: int


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_token(payload: dict, expires_delta: timedelta) -> str:
    to_encode = payload.copy()
    expire = datetime.now(UTC) + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_access_token(user_id: int) -> str:
    return create_token(
        {"sub": str(user_id), "type": "access"},
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )


def refresh_token_key(jti: str) -> str:
    return f"refresh_token:{jti}"


def create_refresh_token(user_id: int) -> tuple[str, str]:
    jti = str(uuid.uuid4())
    refresh = create_token(
        {"sub": str(user_id), "type": "refresh", "jti": jti},
        timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )
    return refresh, jti


def store_refresh_token(jti: str, user_id: int) -> None:
    try:
        redis_client.set(refresh_token_key(jti), str(user_id), ex=REFRESH_TTL_SECONDS)
    except RedisError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Redis indisponível") from exc


def get_refresh_token_owner(jti: str) -> Optional[str]:
    try:
        return redis_client.get(refresh_token_key(jti))
    except RedisError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Redis indisponível") from exc


def rotate_refresh_token(old_jti: str, new_jti: str, user_id: int) -> None:
    try:
        with redis_client.pipeline() as pipeline:
            pipeline.delete(refresh_token_key(old_jti))
            pipeline.set(refresh_token_key(new_jti), str(user_id), ex=REFRESH_TTL_SECONDS)
            pipeline.execute()
    except RedisError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Redis indisponível") from exc


def revoke_refresh_token(jti: str) -> None:
    try:
        redis_client.delete(refresh_token_key(jti))
    except RedisError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Redis indisponível") from exc


def count_active_refresh_tokens() -> int:
    total = 0
    try:
        for _ in redis_client.scan_iter(match="refresh_token:*", count=500):
            total += 1
    except RedisError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Redis indisponível") from exc
    return total


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido ou expirado")


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    payload = decode_token(token)
    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Tipo de token inválido")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")

    user = db.query(User).filter(User.id == int(user_id), User.is_active == True).first()  # noqa: E712
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuário não encontrado")
    return user


@app.on_event("startup")
def on_startup() -> None:
    Base.metadata.create_all(bind=engine)


@app.get("/")
async def root():
    return {
        "mensagem": "Bem-vindo à Calculadora API",
        "autenticacao": {
            "register": "POST /auth/register",
            "login": "POST /auth/login",
            "refresh": "POST /auth/refresh",
            "logout": "POST /auth/logout",
            "dashboard": "GET /dashboard",
        },
        "observacao": "As operações de cálculo exigem token JWT Bearer.",
    }


@app.get("/health", response_class=PlainTextResponse)
async def health() -> str:
    return "OK"


@app.get("/health/containers")
async def health_containers():
    postgres_status = "up"
    postgres_error: Optional[str] = None
    redis_status = "up"
    redis_error: Optional[str] = None

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:
        postgres_status = "down"
        postgres_error = str(exc)
    try:
        redis_client.ping()
    except RedisError as exc:
        redis_status = "down"
        redis_error = str(exc)

    services = {
        "calculadora-api": "up",
        "postgres": postgres_status,
        "redis": redis_status,
    }
    all_up = all(status_service == "up" for status_service in services.values())

    payload = {
        "status": "up" if all_up else "degraded",
        "services": services,
    }
    if postgres_error:
        payload.setdefault("errors", {})
        payload["errors"]["postgres"] = postgres_error
    if redis_error:
        payload.setdefault("errors", {})
        payload["errors"]["redis"] = redis_error

    return JSONResponse(
        status_code=status.HTTP_200_OK if all_up else status.HTTP_503_SERVICE_UNAVAILABLE,
        content=payload,
    )


@app.post("/auth/register", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: UserRegisterRequest, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == payload.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Nome de usuário já cadastrado")

    existing_email = db.query(User).filter(User.email == payload.email).first()
    if existing_email:
        raise HTTPException(status_code=400, detail="E-mail já cadastrado")

    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        is_active=True,
    )
    db.add(user)
    db.commit()
    return MessageResponse(message="Usuário cadastrado com sucesso")


@app.post("/auth/login", response_model=AuthTokensResponse)
async def login(payload: UserLoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username, User.is_active == True).first()  # noqa: E712
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais inválidas")

    access_token = create_access_token(user.id)
    refresh_token, jti = create_refresh_token(user.id)
    store_refresh_token(jti, user.id)
    return AuthTokensResponse(access_token=access_token, refresh_token=refresh_token)


@app.post("/auth/refresh", response_model=AuthTokensResponse)
async def refresh_token(payload: TokenRefreshRequest, db: Session = Depends(get_db)):
    token_payload = decode_token(payload.refresh_token)
    if token_payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Tipo de token inválido")

    user_id = token_payload.get("sub")
    jti = token_payload.get("jti")
    if not user_id or not jti:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token de refresh inválido")

    stored_user_id = get_refresh_token_owner(jti)
    if not stored_user_id or stored_user_id != str(user_id):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token inválido ou expirado")

    user = db.query(User).filter(User.id == int(user_id), User.is_active == True).first()  # noqa: E712
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuário inválido")

    new_access_token = create_access_token(user.id)
    new_refresh_token, new_jti = create_refresh_token(user.id)
    rotate_refresh_token(jti, new_jti, user.id)

    return AuthTokensResponse(access_token=new_access_token, refresh_token=new_refresh_token)


@app.post("/auth/logout", response_model=MessageResponse)
async def logout(payload: TokenRefreshRequest):
    token_payload = decode_token(payload.refresh_token)
    if token_payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Tipo de token inválido")

    jti = token_payload.get("jti")
    if not jti:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token de refresh inválido")

    revoke_refresh_token(jti)

    return MessageResponse(message="Logout realizado com sucesso")


@app.get("/dashboard", response_model=DashboardResponse)
async def dashboard(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    total_usuarios = db.query(User).count()
    total_refresh_tokens_ativos = count_active_refresh_tokens()

    return DashboardResponse(
        usuario=current_user.username,
        email=current_user.email,
        total_usuarios=total_usuarios,
        total_refresh_tokens_ativos=total_refresh_tokens_ativos,
        total_operacoes_disponiveis=27,
    )


@app.get("/dashboard/ui", response_class=HTMLResponse)
async def dashboard_ui():
    return """
<!doctype html>
<html lang=\"pt-BR\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Dashboard - Calculadora API</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; background: #f6f8fa; color: #111; }
    .card { background: #fff; padding: 16px; border-radius: 8px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
    input, button { padding: 8px; margin: 4px 0; width: 100%; box-sizing: border-box; }
    button { cursor: pointer; font-weight: 600; }
    pre { background: #111; color: #0f0; padding: 12px; border-radius: 6px; overflow: auto; }
  </style>
</head>
<body>
  <h1>Dashboard da Calculadora API</h1>
  <div class=\"card\">
    <h2>Login</h2>
    <input id=\"username\" placeholder=\"username\" />
    <input id=\"password\" type=\"password\" placeholder=\"password\" />
    <button onclick=\"login()\">Entrar</button>
  </div>
  <div class=\"card\">
    <h2>Dashboard</h2>
    <button onclick=\"loadDashboard()\">Carregar dashboard</button>
    <button onclick=\"logout()\">Logout</button>
    <pre id=\"output\">Sem dados.</pre>
  </div>
  <script>
    let accessToken = \"\";
    let refreshToken = \"\";
    const output = document.getElementById(\"output\");

    async function login() {
      const username = document.getElementById(\"username\").value;
      const password = document.getElementById(\"password\").value;
      const response = await fetch(\"/auth/login\", {
        method: \"POST\",
        headers: { \"Content-Type\": \"application/json\" },
        body: JSON.stringify({ username, password })
      });
      const data = await response.json();
      if (!response.ok) {
        output.textContent = JSON.stringify(data, null, 2);
        return;
      }
      accessToken = data.access_token;
      refreshToken = data.refresh_token;
      output.textContent = \"Login realizado com sucesso. Clique em 'Carregar dashboard'.\";
    }

    async function loadDashboard() {
      const response = await fetch(\"/dashboard\", {
        headers: { \"Authorization\": `Bearer ${accessToken}` }
      });
      const data = await response.json();
      output.textContent = JSON.stringify(data, null, 2);
    }

    async function logout() {
      const response = await fetch(\"/auth/logout\", {
        method: \"POST\",
        headers: { \"Content-Type\": \"application/json\" },
        body: JSON.stringify({ refresh_token: refreshToken })
      });
      const data = await response.json();
      accessToken = \"\";
      refreshToken = \"\";
      output.textContent = JSON.stringify(data, null, 2);
    }
  </script>
</body>
</html>
    """


calc_router = APIRouter(dependencies=[Depends(get_current_user)])


@calc_router.post("/soma", response_model=ResultadoResponse)
async def soma(operacao: OperacaoRequest):
    resultado = operacao.numero1 + operacao.numero2
    return ResultadoResponse(resultado=resultado, operacao=f"{operacao.numero1} + {operacao.numero2} = {resultado}")


@calc_router.post("/subtracao", response_model=ResultadoResponse)
async def subtracao(operacao: OperacaoRequest):
    resultado = operacao.numero1 - operacao.numero2
    return ResultadoResponse(resultado=resultado, operacao=f"{operacao.numero1} - {operacao.numero2} = {resultado}")


@calc_router.post("/multiplicacao", response_model=ResultadoResponse)
async def multiplicacao(operacao: OperacaoRequest):
    resultado = operacao.numero1 * operacao.numero2
    return ResultadoResponse(resultado=resultado, operacao=f"{operacao.numero1} * {operacao.numero2} = {resultado}")


@calc_router.post("/divisao", response_model=ResultadoResponse)
async def divisao(operacao: OperacaoRequest):
    if operacao.numero2 == 0:
        raise HTTPException(status_code=400, detail="Divisão por zero não é permitida")
    resultado = operacao.numero1 / operacao.numero2
    return ResultadoResponse(resultado=resultado, operacao=f"{operacao.numero1} / {operacao.numero2} = {resultado}")


@calc_router.post("/porcentagem", response_model=ResultadoResponse)
async def porcentagem(operacao: OperacaoRequest):
    resultado = (operacao.numero1 / 100) * operacao.numero2
    return ResultadoResponse(resultado=resultado, operacao=f"{operacao.numero1}% de {operacao.numero2} = {resultado}")


@calc_router.post("/regra-de-tres", response_model=ResultadoResponse)
async def regra_de_tres(operacao: RegraDeTresRequest):
    if operacao.valor_a == 0:
        raise HTTPException(status_code=400, detail="Na regra de 3, 'valor_a' não pode ser zero")
    resultado = (operacao.valor_b * operacao.valor_c) / operacao.valor_a
    return ResultadoResponse(
        resultado=resultado,
        operacao=f"{operacao.valor_a} : {operacao.valor_b} = {operacao.valor_c} : x, x = {resultado}",
    )


@calc_router.post("/media-aritmetica", response_model=ResultadoResponse)
async def media_aritmetica(operacao: ListaNumerosRequest):
    if len(operacao.numeros) == 0:
        raise HTTPException(status_code=400, detail="A lista de números não pode estar vazia")
    resultado = sum(operacao.numeros) / len(operacao.numeros)
    return ResultadoResponse(resultado=resultado, operacao=f"média aritmética de {operacao.numeros} = {resultado}")


@calc_router.post("/media-ponderada", response_model=ResultadoResponse)
async def media_ponderada(operacao: MediaPonderadaRequest):
    if len(operacao.valores) == 0 or len(operacao.pesos) == 0:
        raise HTTPException(status_code=400, detail="As listas de valores e pesos não podem estar vazias")
    if len(operacao.valores) != len(operacao.pesos):
        raise HTTPException(status_code=400, detail="As listas de valores e pesos devem ter o mesmo tamanho")
    soma_pesos = sum(operacao.pesos)
    if soma_pesos == 0:
        raise HTTPException(status_code=400, detail="A soma dos pesos não pode ser zero")
    resultado = sum(v * p for v, p in zip(operacao.valores, operacao.pesos)) / soma_pesos
    return ResultadoResponse(
        resultado=resultado,
        operacao=f"média ponderada de valores={operacao.valores}, pesos={operacao.pesos} = {resultado}",
    )


@calc_router.post("/porcentagem-variacao", response_model=ResultadoResponse)
async def porcentagem_variacao(operacao: VariacaoPercentualRequest):
    if operacao.valor_inicial == 0:
        raise HTTPException(status_code=400, detail="O valor inicial não pode ser zero")
    resultado = ((operacao.valor_final - operacao.valor_inicial) / operacao.valor_inicial) * 100
    return ResultadoResponse(
        resultado=resultado,
        operacao=f"variação percentual de {operacao.valor_inicial} para {operacao.valor_final} = {resultado}%",
    )


@calc_router.post("/juros-simples", response_model=ResultadoResponse)
async def juros_simples(operacao: JurosRequest):
    if operacao.capital < 0 or operacao.tempo < 0:
        raise HTTPException(status_code=400, detail="Capital e tempo devem ser maiores ou iguais a zero")
    juros = operacao.capital * (operacao.taxa / 100) * operacao.tempo
    resultado = operacao.capital + juros
    return ResultadoResponse(
        resultado=resultado,
        operacao=f"juros simples: C={operacao.capital}, i={operacao.taxa}%, t={operacao.tempo}, M={resultado}",
    )


@calc_router.post("/juros-compostos", response_model=ResultadoResponse)
async def juros_compostos(operacao: JurosRequest):
    if operacao.capital < 0 or operacao.tempo < 0:
        raise HTTPException(status_code=400, detail="Capital e tempo devem ser maiores ou iguais a zero")
    resultado = operacao.capital * ((1 + (operacao.taxa / 100)) ** operacao.tempo)
    return ResultadoResponse(
        resultado=resultado,
        operacao=f"juros compostos: C={operacao.capital}, i={operacao.taxa}%, t={operacao.tempo}, M={resultado}",
    )


@calc_router.post("/fatorial", response_model=ResultadoResponse)
async def fatorial(operacao: InteiroRequest):
    if operacao.numero < 0:
        raise HTTPException(status_code=400, detail="Fatorial só é definido para inteiros não negativos")
    resultado = math.factorial(operacao.numero)
    return ResultadoResponse(resultado=float(resultado), operacao=f"{operacao.numero}! = {resultado}")


@calc_router.post("/modulo", response_model=ResultadoResponse)
async def modulo(operacao: InteirosRequest):
    if operacao.numero2 == 0:
        raise HTTPException(status_code=400, detail="Divisão por zero não é permitida")
    resultado = operacao.numero1 % operacao.numero2
    return ResultadoResponse(resultado=float(resultado), operacao=f"{operacao.numero1} % {operacao.numero2} = {resultado}")


@calc_router.post("/valor-absoluto", response_model=ResultadoResponse)
async def valor_absoluto(operacao: OperacaoUnariaRequest):
    resultado = abs(operacao.numero)
    return ResultadoResponse(resultado=resultado, operacao=f"|{operacao.numero}| = {resultado}")


@calc_router.post("/graus-para-radianos", response_model=ResultadoResponse)
async def graus_para_radianos(operacao: OperacaoUnariaRequest):
    resultado = math.radians(operacao.numero)
    return ResultadoResponse(resultado=resultado, operacao=f"{operacao.numero}° = {resultado} rad")


@calc_router.post("/radianos-para-graus", response_model=ResultadoResponse)
async def radianos_para_graus(operacao: OperacaoUnariaRequest):
    resultado = math.degrees(operacao.numero)
    return ResultadoResponse(resultado=resultado, operacao=f"{operacao.numero} rad = {resultado}°")


@calc_router.post("/mmc", response_model=ResultadoResponse)
async def mmc(operacao: InteirosRequest):
    if operacao.numero1 == 0 and operacao.numero2 == 0:
        raise HTTPException(status_code=400, detail="MMC de 0 e 0 é indefinido")
    divisor_comum = math.gcd(operacao.numero1, operacao.numero2)
    resultado = abs(operacao.numero1 * operacao.numero2) // divisor_comum
    return ResultadoResponse(resultado=float(resultado), operacao=f"mmc({operacao.numero1}, {operacao.numero2}) = {resultado}")


@calc_router.post("/mdc", response_model=ResultadoResponse)
async def mdc(operacao: InteirosRequest):
    resultado = math.gcd(operacao.numero1, operacao.numero2)
    return ResultadoResponse(resultado=float(resultado), operacao=f"mdc({operacao.numero1}, {operacao.numero2}) = {resultado}")


@calc_router.post("/equacao-2-grau", response_model=EquacaoSegundoGrauResponse)
async def equacao_2_grau(operacao: EquacaoSegundoGrauRequest):
    if operacao.a == 0:
        raise HTTPException(status_code=400, detail="Em equação de 2º grau, 'a' não pode ser zero")
    delta = (operacao.b ** 2) - (4 * operacao.a * operacao.c)
    if delta >= 0:
        raiz_delta = math.sqrt(delta)
        x1 = (-operacao.b + raiz_delta) / (2 * operacao.a)
        x2 = (-operacao.b - raiz_delta) / (2 * operacao.a)
    else:
        raiz_delta = complex(0, math.sqrt(-delta))
        x1 = (-operacao.b + raiz_delta) / (2 * operacao.a)
        x2 = (-operacao.b - raiz_delta) / (2 * operacao.a)
    return EquacaoSegundoGrauResponse(
        delta=delta,
        raizes=[str(x1), str(x2)],
        operacao=f"{operacao.a}x² + {operacao.b}x + {operacao.c} = 0",
    )


@calc_router.post("/imc", response_model=ResultadoResponse)
async def imc(operacao: ImcRequest):
    if operacao.altura <= 0:
        raise HTTPException(status_code=400, detail="A altura deve ser maior que zero")
    resultado = operacao.peso / (operacao.altura ** 2)
    return ResultadoResponse(
        resultado=resultado,
        operacao=f"IMC para peso={operacao.peso}kg e altura={operacao.altura}m = {resultado}",
    )


@calc_router.post("/potencia", response_model=ResultadoResponse)
async def potencia(operacao: OperacaoAvancadaRequest):
    if operacao.potencia is None:
        raise HTTPException(status_code=400, detail="O parâmetro 'potencia' é obrigatório")
    resultado = math.pow(operacao.numero, operacao.potencia)
    return ResultadoResponse(resultado=resultado, operacao=f"{operacao.numero} ^ {operacao.potencia} = {resultado}")


@calc_router.post("/raiz-quadrada", response_model=ResultadoResponse)
async def raiz_quadrada(operacao: OperacaoUnariaRequest):
    if operacao.numero < 0:
        raise HTTPException(status_code=400, detail="Não é possível calcular raiz quadrada de número negativo")
    resultado = math.sqrt(operacao.numero)
    return ResultadoResponse(resultado=resultado, operacao=f"√{operacao.numero} = {resultado}")


@calc_router.post("/raiz-cubica", response_model=ResultadoResponse)
async def raiz_cubica(operacao: OperacaoUnariaRequest):
    resultado = operacao.numero ** (1 / 3)
    return ResultadoResponse(resultado=resultado, operacao=f"∛{operacao.numero} = {resultado}")


@calc_router.post("/logaritmo", response_model=ResultadoResponse)
async def logaritmo(operacao: OperacaoUnariaRequest):
    if operacao.numero <= 0:
        raise HTTPException(status_code=400, detail="Logaritmo só é definido para números positivos")
    resultado = math.log(operacao.numero)
    return ResultadoResponse(resultado=resultado, operacao=f"ln({operacao.numero}) = {resultado}")


@calc_router.post("/seno", response_model=ResultadoResponse)
async def seno(operacao: OperacaoUnariaRequest):
    resultado = math.sin(operacao.numero)
    return ResultadoResponse(resultado=resultado, operacao=f"sin({operacao.numero}) = {resultado}")


@calc_router.post("/cosseno", response_model=ResultadoResponse)
async def cosseno(operacao: OperacaoUnariaRequest):
    resultado = math.cos(operacao.numero)
    return ResultadoResponse(resultado=resultado, operacao=f"cos({operacao.numero}) = {resultado}")


@calc_router.post("/tangente", response_model=ResultadoResponse)
async def tangente(operacao: OperacaoUnariaRequest):
    resultado = math.tan(operacao.numero)
    return ResultadoResponse(resultado=resultado, operacao=f"tan({operacao.numero}) = {resultado}")


app.include_router(calc_router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
