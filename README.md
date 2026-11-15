Feature Flag Management System

1. Project Overview

The Feature Flag Management System is a web-based application developed using Python and FastAPI. It helps administrators manage application features, control feature releases, and decide which users can access specific features.

2. Technologies Used

- Python
- FastAPI
- PostgreSQL
- SQLAlchemy
- Alembic
- HTML, CSS and JavaScript
- JWT Authentication
- Pytest

3. Main Features

- Admin authentication using JWT.
- Feature flag creation and management.
- Multiple environment management.
- Targeting rules creation, updating and deletion.
- User groups and group memberships.
- Stable percentage-based feature rollout.
- Feature evaluation with reason codes.
- Global feature kill switch.
- Audit logs.
- Analytics and evaluation statistics.

4. Project Structure

- "main.py" – Main FastAPI application.
- "milestone3_api.py" – Milestone 3 API endpoints.
- "models.py" – Database models.
- "database.py" – Database connection configuration.
- "services/" – Business logic and service functions.
- "alembic/" – Database migration files.
- "tests/" – Automated test files.
- "dashboard.html" – Admin dashboard.
- "index.html" – Application home page.
- "requirements.txt" – Python dependencies.
- ".env" – Environment configuration (not committed to GitHub).

5. Installation and Setup

1. Clone the project repository.
2. Open the project folder in VS Code.
3. Create and activate a Python virtual environment.
4. Install the required dependencies:

python -m pip install -r requirements.txt

5. Configure the required environment variables in ".env".
6. Apply database migrations:

python -m alembic upgrade head

7. Start the application:

python -m uvicorn main:app --reload

6. Accessing the Application

- Dashboard: http://127.0.0.1:8000/dashboard
- API Documentation: http://127.0.0.1:8000/docs

7. Automated Testing

Pytest is used to test database setup, evaluation logic, targeting rules, percentage rollout and error handling.

Run the tests using:

python -m pytest tests -v

Current test result: 21 tests passed.

8. Milestone 3 Implementation

Milestone 3 includes admin authorization, targeting rules, user groups, percentage rollout, feature evaluation, kill switch functionality, database migrations and automated testing.

9. Conclusion

This project demonstrates how feature flags can be managed through a centralized web application, helping administrators control feature availability and release features to selected users.