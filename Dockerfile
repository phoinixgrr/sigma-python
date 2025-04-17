# Use a slim base Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy only the necessary files
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the app
COPY . .

# Set environment variables (can be overridden)
ENV FLASK_APP=sigma_api.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=8080

# Expose port
EXPOSE 8080

# Start the app
CMD ["flask", "run"]

