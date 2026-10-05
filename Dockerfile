FROM docker.io/library/debian:bookworm-slim
WORKDIR /app
COPY clea ./backend/clea
COPY frontend/ ./frontend/
WORKDIR /app/backend
EXPOSE 8080
CMD ["./clea"]
