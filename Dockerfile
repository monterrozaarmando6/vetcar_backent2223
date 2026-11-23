FROM eclipse-temurin:21-jdk
WORKDIR /app

COPY ApiServer.java /app/ApiServer.java
RUN mkdir -p /app/out && javac -d /app/out /app/ApiServer.java

ENV PORT=8080
ENV DATA_DIR=/data
EXPOSE 8080

CMD ["java", "-cp", "out", "com.veterinaria.ApiServer"]
