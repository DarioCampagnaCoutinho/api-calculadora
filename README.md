# Calculadora FastAPI com JWT, PostgreSQL e Redis

API REST de calculadora com autenticação JWT, refresh token com sessão no Redis, logout e dashboard protegida.

## O que foi adicionado

- Cadastro de usuário (`POST /auth/register`)
- Login com JWT (`POST /auth/login`)
- Refresh token com rotação (`POST /auth/refresh`) e expiração no Redis
- Logout com revogação de refresh token (`POST /auth/logout`)
- Dashboard protegida (`GET /dashboard`)
- Dashboard web simples (`GET /dashboard/ui`)
- Todos os endpoints de cálculo protegidos por token Bearer

## Diagrama do fluxo

Veja `docs/fluxo-autenticacao.mmd` para o diagrama de autenticação.

## Stack

- FastAPI
- PostgreSQL
- Redis
- SQLAlchemy
- JWT (`python-jose`)
- Hash de senha com `passlib` + `bcrypt`

## Executar com Docker Compose

```bash
docker-compose up --build
```

Serviços:
- API: `http://localhost:8000`
- Swagger: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
- PostgreSQL: `localhost:5432`
- Redis: `localhost:6379`

## Variáveis de ambiente

A configuração padrão já está no `docker-compose.yml`:

- `DATABASE_URL=postgresql://postgres:postgres@postgres:5432/calculadora`
- `REDIS_URL=redis://redis:6379/0`
- `JWT_SECRET_KEY=change-this-secret-in-production`
- `JWT_ALGORITHM=HS256`
- `ACCESS_TOKEN_EXPIRE_MINUTES=15`
- `REFRESH_TOKEN_EXPIRE_DAYS=7`

## Fluxo de autenticação

### 1. Cadastrar usuário

```bash
curl -X POST "http://localhost:8000/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"dario","email":"dario@email.com","password":"123456"}'
```

### 2. Login

```bash
curl -X POST "http://localhost:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"dario","password":"123456"}'
```

Resposta esperada:

```json
{
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "bearer"
}
```

### 3. Usar token nas operações

```bash
curl -X POST "http://localhost:8000/soma" \
  -H "Authorization: Bearer SEU_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"numero1":10,"numero2":5}'
```

### 4. Renovar sessão

```bash
curl -X POST "http://localhost:8000/auth/refresh" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"SEU_REFRESH_TOKEN"}'
```

### 5. Logout

```bash
curl -X POST "http://localhost:8000/auth/logout" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"SEU_REFRESH_TOKEN"}'
```

## Dashboard protegida

```bash
curl -X GET "http://localhost:8000/dashboard" \
  -H "Authorization: Bearer SEU_ACCESS_TOKEN"
```

Retorna dados do usuário autenticado e métricas básicas da API.

## Dashboard web (navegador)

Acesse:

- `http://localhost:8000/dashboard/ui`

Essa tela permite:
- Fazer login
- Consultar a dashboard protegida
- Fazer logout

## Endpoints de cálculo (todos exigem Bearer token)

### Básicos
- `POST /soma`
- `POST /subtracao`
- `POST /multiplicacao`
- `POST /divisao`
- `POST /porcentagem`
- `POST /regra-de-tres`
- `POST /media-aritmetica`
- `POST /media-ponderada`
- `POST /porcentagem-variacao`
- `POST /juros-simples`
- `POST /juros-compostos`
- `POST /fatorial`
- `POST /modulo`
- `POST /valor-absoluto`
- `POST /graus-para-radianos`
- `POST /radianos-para-graus`
- `POST /mmc`
- `POST /mdc`
- `POST /equacao-2-grau`
- `POST /imc`

### Trigonométricos e avançados
- `POST /potencia`
- `POST /raiz-quadrada`
- `POST /raiz-cubica`
- `POST /logaritmo`
- `POST /seno`
- `POST /cosseno`
- `POST /tangente`

## Observações

- O `access_token` é de curta duração (padrão 15 min).
- O `refresh_token` é persistido no Redis com TTL e pode ser revogado no logout.
- O endpoint de refresh revoga o refresh token antigo e emite um novo.
