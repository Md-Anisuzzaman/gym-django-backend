
# Gym Management System - Backend API

This project is a comprehensive backend API designed to manage the entire operational logic of a gym. From member and trainer management to financial tracking, this system provides a robust foundation for streamlining gym business processes. The API is built using Django, ensuring scalability and ease of integration with frontend applications.

## Features

#### Member Management

- Member Registration: Add, update, and delete member profiles.

- Attendance Tracking: Track member entry and exit times in real-time.

- Activity Tracking: Associate members with specific gym activities or programs.

### Trainer & Employee Management

- Shift Management: Manage trainers' daily duty schedules, including shift timings and weekly holidays.

- Attendance Tracking: Record trainer entry and exit times.

- Monthly Workday Calculations: Automatically calculate the total number of workdays for each trainer.

### Payment Management

- Member Payments: Record and track member monthly or any payments.

- Payment History: Maintain a detailed history of payments made by each member.

### Financial Tracking

- Earnings Calculation: Calculate total earnings from member subscriptions on a monthly and annual basis.

- Expense Management: Track gym operational expenses.

- Profit Analysis: Generate reports showing monthly and annual profit or loss.


### Technologies Used

- Framework: Django (Python)

- Database: MySQL

- Authentication & Authorization: JWT-based authentication for secure access.

- API Documentation: 

- Testing: Unit tests to ensure code quality and reliability.

- Version Control: Git for source control.

## Installation
Clone Repository:
```bash
git clone https://github.com/Md-Anisuzzaman/powerGym_Backend.git
cd powerGym_Backend
```
Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```
Install dependencies: 
```bash
pip install -r requirements.txt
```

Set up the database:
- Configure the database in settings.py.
- Apply migrations:
```bash
python manage.py makemigration
python manage.py migrate
```

Run the development server:
```bash
python manage.py runserver 
```

#### N.B: The application is under process so much work not yet done

### Future Enhancements

Mobile App Integration: API support for mobile apps.

Advanced Analytics: Integration with BI tools for detailed analytics.

Notifications: Automated reminders for member renewals and payment due dates.

Third-party Integrations: Integration with payment gateways and attendance devices.
