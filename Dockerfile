# Use an official Node.js runtime as a parent image
FROM node:16.19.1

# Set the working directory to /app
WORKDIR /app

# Copy the package.json and package-lock.json files to the container
COPY package*.json ./

# Install the dependencies
RUN npm install --lagecy-peer-deps

# Copy the rest of the application code to the container
COPY . .

# Set environment variables for MongoDB and Redis

# ENV MONGO_URI mongodb://mongo:27017/backend
# ENV REDIS_HOST redis
# ENV REDIS_PORT 6379

# Expose port 3000 for the application
EXPOSE 3000
# Start the application
CMD ["npm", "start"]
