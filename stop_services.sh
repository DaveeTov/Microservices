#!/bin/bash
# Script para detener todos los microservicios del proyecto 

LOG_DIR="$(pwd)/logs"

# Función para detener un servicio 
stop_services() {
    local service_name=$1
    local pid_file="$LOG_DIR/$service_name.pid"

    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if ps -p $pid > /dev/null; then
            echo "Deteniendo $service_name (PID: $pid)..."
            kill $pid
            rm "$pid_file"
        else
            echo "No se encontró un proceso activo para $service_name"
            rm "$pid_file"
        fi
    else 
        echo "No se encontró el archivo PID para $service_name"
    fi
}

# Detenemos cada microservicio 
stop_services "api_gateway"
stop_services "auth_service"
stop_services "user_service"
stop_services "task_service"

echo "Todos los servicios han sido detenidos."
