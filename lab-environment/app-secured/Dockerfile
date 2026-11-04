# ==========================================
# Giai đoạn 1: Build file JAR từ mã nguồn
# ==========================================
FROM maven:3.9-eclipse-temurin-17-alpine AS builder
WORKDIR /build

# Tận dụng Docker cache cho dependencies
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy toàn bộ mã nguồn và đóng gói
COPY src ./src
RUN mvn clean package -DskipTests

# ==========================================
# Giai đoạn 2: Runtime image tối ưu dung lượng
# ==========================================
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

# Tạo non-root user để tăng tính bảo mật cho container
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# Copy file .jar đã đóng gói từ giai đoạn build
COPY --from=builder /build/target/*.jar app.jar

ENV SERVER_PORT=8081
EXPOSE 8081

ENTRYPOINT ["java", "-jar", "app.jar"]
