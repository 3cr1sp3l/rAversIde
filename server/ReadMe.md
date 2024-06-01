# RAversIde Server

## Introduction

Welcome to the RAversIde Server! This server powers the RAversIde Plugin for Ghidra by providing essential backend services. This guide will help you get started with running the server, either using the hosted version, a Docker container, or by setting it up locally for development and testing.

## Table of Contents

1. [Hosted Server](#hosted-server)
2. [Docker Container](#docker-container)
3. [Local Development](#local-development)
4. [Usage](#usage)

## Hosted Server

The RAversIde Server is already hosted and ready for use at [raverside-server.aymeric-daniel.com](http://raverside-server.aymeric-daniel.com/). The RAversIde Plugin is automatically connected to this endpoint.

## Docker Container

If you prefer to run the server locally using Docker, you can easily do so by following these steps:

1. **Pull the Docker Image**:
    
    ```bash
    sudo docker pull ayrick/raverside-server:latest
    ```
    
2. **Run the Docker Container**:
    
    ```bash
    sudo docker run -d --name raverside-server -p 5001:5001 ayrick/raverside-server:latest
    
    ```
    

This command will download the latest RAversIde Server image and run it in a Docker container, exposing it on port 5001.

## Local Development

For those interested in modifying the server code and running it locally, follow these steps:

1. **Clone the Repository**:
    
    ```bash
    git clone https://github.com/aymeric-daniel/raverside-server.git
    ```
    
2. **Navigate to the Server Directory**:
    
    ```bash
    cd raverside-server
    ```
    
3. **Install the Required Dependencies**:
    
    ```bash
    pip install -r requirements.txt
    ```
    
4. **Run the Server**:
    
    ```bash
    python3 server.py
    ```
    

This will start the server locally, allowing you to make and test changes as needed.

## Usage

Once the server is running, whether hosted, in a Docker container, or locally, it will listen for requests from the RAversIde Plugin for Ghidra. Ensure that your plugin is configured to communicate with the correct server endpoint.

- **Hosted Server**: `http://raverside-server.aymeric-daniel.com`
- **Docker Container**: `http://localhost:5001` (or the port you configured)
- **Local Development**: `http://localhost:5001` (or the port you configured)
