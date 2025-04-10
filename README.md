# Load Balancer Implementation

A demonstration of different load balancing algorithms using Python Flask and Docker.

## Overview
This project simulates a load balancing system with:
- 1 Load Balancer
- 4 Backend Servers
- 1 Client generating requests

The system demonstrates how different load balancing algorithms handle server load distribution and prevent server overload.

## Load Balancing Algorithms
1. **Round Robin**
   - Distributes requests sequentially across all servers
   - Simple and fair distribution

2. **Source Hashing**
   - Routes requests based on a hash of the request parameters
   - Similar requests go to the same server

3. **Least Loaded**
   - Sends requests to the server with the lowest current load
   - Prevents server overload

## Project Structure
```
Project/
├── Client/
│   ├── Dockerfile
│   ├── client.py
│   ├── performance_metrics.py
│   └── requirements.txt
├── Server/
│   ├── LoadBalancer/
│   │   ├── Dockerfile
│   │   ├── loadbalancer.py
│   │   └── requirements.txt
│   ├── Server1/
│   │   ├── Dockerfile
│   │   ├── server.py
│   │   └── requirements.txt
│   ├── Server2/
│   ├── Server3/
│   └── Server4/
└── docker-compose.yml
```

## Features
- **Multiple Load Balancing Algorithms**: Compare performance of different strategies
- **Real-time Load Monitoring**: Track server load and health
- **Performance Metrics**: Measure and compare algorithm effectiveness
- **Docker Containerization**: Easy deployment and scaling
- **Simulated Server Load**: Various task types to demonstrate load handling

## Request Types
The system handles different types of requests:
- **Light Tasks**: Addition, String Length
- **Medium Tasks**: Multiplication, Find Vowels
- **Heavy Tasks**: Factorial, Large List Sorting

## How to Run
1. Clone the repository
```bash
git clone https://github.com/anjaliheda/Load-Balancer.git
cd Load-Balancer
```

2. Run with Docker Compose
```bash
docker-compose up --build
```

## Performance Metrics
The system measures:
- Request Success Rate
- Average Response Time
- Server Load Distribution
- Failed Request Count
- Processing Time per Task Type

## Requirements
- Docker
- Docker Compose
- Python 3.x
- Flask

## Future Improvements
- Web UI for monitoring
- Additional load balancing algorithms
- Database integration
- Real-time metrics visualization
