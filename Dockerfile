FROM node:18-alpine

WORKDIR /app

# Create log directory
RUN mkdir -p /var/log/app && chmod 777 /var/log/app

# Copy package files
COPY package*.json ./

# Install dependencies (including Winston)
RUN npm ci --only=production

# Copy application code
COPY . .

# Expose port
EXPOSE 3000

# Start the application
CMD ["npm", "start"]