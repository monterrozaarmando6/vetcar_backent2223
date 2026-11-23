FROM eclipse-temurin:21-jdk
WORKDIR /app
COPY . /app
# Finds the source even if the hosting platform uses a nested project directory.
RUN SOURCE="$(find /app -path '*/src/main/java/com/veterinaria/ApiServer.java' -print -quit)" \
    && test -n "$SOURCE" \
    && mkdir -p /app/out \
    && javac -d /app/out "$SOURCE"
ENV PORT=8080
ENV DATA_DIR=/data
EXPOSE 8080
VOLUME ["/data"]
CMD ["java", "-cp", "out", "com.veterinaria.ApiServer"]
