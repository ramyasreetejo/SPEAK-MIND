# Speak Mind

Speak Mind backend application is the backend of a social networking platform, providing users with the ability to sign up, log in, and share their thoughts as posts. Users can follow each other to receive posts in reverse chronological order on their personalized timelines. Built using Golang, MongoDB, and JWT for authentication, it features a range of functionalities including CRUD operations for thoughts, user following management, and secure user authentication.

**Context**: Each thought, in the form of text (max 250 char string), is a post on the platform.

### Key Features:

* **_Authentication_**: Secure user signup and login routes using JWT for token-based authentication.
* **_User Management_**: Admin and regular user access controls with CRUD operations for user management.
* **_Timeline Management_**: Aggregates and displays user and following posts in reverse chronological order with pagination.
* **_Thoughts Management_**: CRUD operations for user thoughts including adding, deleting, liking, and unliking.
* **_Follow System_**: Allows users to follow/unfollow others based on partial username searches using regex queries.
  
### Tech Stack:

* **_Backend_**: Golang with net/http for routing and server implementation.
* **_Authentication_**: jwt-go package for secure token-based authentication and authorization.
* **_Database_**: MongoDB for efficient storage and retrieval of user data and thoughts.
  
### Project Responsibilities:

* Designed and implemented RESTful APIs for user authentication, thought management, and follow system.
* Developed MongoDB data models for scalability and performance.
* Implemented robust error handling and security measures to protect user data and ensure system reliability.
  
### Achievements:

* Successfully integrated JWT authentication to secure user routes and manage user sessions effectively.
* Implemented efficient MongoDB aggregation pipelines for timeline management to handle large volumes of data.
  
### Tools and Technologies:

Golang, net/http, JWT (JSON Web Tokens), MongoDB, RESTful APIs, Authentication and Authorization, CRUD Operations, Regex Query Handling.

### Setup and run the server:

* Clone the repository onto your local workspace.
* Make sure Go and Mongodb are installed on your system.
* cd to the cloned repo and run **_go mod tidy_** to install all dependencies.
* Modify the .env file accordingly and run **_go run main.go_** to start the go server on 9000 port (default from .env).
* Access and test apis via Postman.

Ta-da!! You have a running Speak Mind server on your local :)
