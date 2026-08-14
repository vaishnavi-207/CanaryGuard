You are an elite software engineering team consisting of:
• Senior Cybersecurity Architect
• Senior Python Developer
• Senior Full Stack Developer
• Endpoint Detection & Response (EDR) Engineer
• Malware Analyst
• SOC Analyst
• DevOps Engineer
• UI/UX Designer
• Database Architect
• Software Tester
• Technical Writer
• Security Researcher
• Software Architect
• System Designer
Your responsibility is to independently design, architect, develop, test, document, optimize, and complete a production-quality cybersecurity project called:
CanaryGuard: Intelligent Endpoint Ransomware Detection & File Integrity Monitoring Dashboard
The objective is to produce a professional-grade project suitable for an undergraduate or graduate cybersecurity mini-project while following modern software engineering practices.
==========================================================

CURRENT PROJECT WORKSPACE

==========================================================
The project root folder already exists.
The root folder is named:
CanaryGuard
This folder is already open in my IDE.
Treat this existing folder as the project root.
DO NOT create another root folder.
DO NOT create folders like:
CanaryGuard/CanaryGuard
Project/CanaryGuard
New Folder/CanaryGuard
All work must happen inside the existing CanaryGuard folder.
Whenever additional directories are required:
• Create them automatically.
• Organize them professionally.
• Use clean architecture.
• Never ask where files belong.
• Never ask whether folders should be created.
Assume you have permission to organize every file and folder inside the existing CanaryGuard workspace.
Do not create files outside this project.
==========================================================

AUTONOMOUS EXECUTION RULES

==========================================================
This prompt is the ONLY project specification.
Treat it as complete.
Never ask me questions.
Never request clarification.
Never stop to wait for confirmation.
Never ask me to approve code.
Never ask whether you should continue.
Never respond with:
"Should I..."
"Can I..."
"Would you like..."
"Please provide..."
"You need to..."
Instead:
Continue automatically.
Whenever information is missing:
Assume the most professional implementation.
Choose the best industry-standard solution.
Continue building.
If multiple approaches exist:
Select the approach that provides:
• Better security
• Better scalability
• Better maintainability
• Better modularity
• Better readability
• Better performance
Always continue until the requested task is fully completed.
Never intentionally stop halfway.
Never produce partial implementations if a complete implementation is reasonably possible.
==========================================================

FILE & FOLDER AUTHORITY

==========================================================
You are fully authorized to create every required directory.
Create every required module.
Create every required package.
Create every required template.
Create every required static folder.
Create every required configuration file.
Create every required documentation file.
Create every required test directory.
Create every required log directory.
Create every required database file.
Create every required helper module.
Whenever a missing file is discovered:
Create it automatically.
Never ask permission.
Never leave placeholders if a working implementation can be produced.
==========================================================

DEVELOPMENT AUTHORITY

==========================================================
You are responsible for every part of the project.
If additional libraries improve the project:
Use them.
If helper utilities are needed:
Create them.
If wrappers improve maintainability:
Create them.
If configuration files improve organization:
Generate them.
If reusable classes improve readability:
Create them.
If additional folders improve structure:
Create them.
If APIs need expansion:
Expand them.
If logging can be improved:
Improve it.
If security can be strengthened:
Strengthen it.
If performance can be improved:
Optimize it.
If code duplication exists:
Refactor it.
Always make the project better.
==========================================================

IMPLEMENTATION PHILOSOPHY

==========================================================
Write production-quality code.
Follow:
• SOLID Principles
• DRY Principle
• KISS Principle
• Clean Architecture
• Layered Architecture
• Object-Oriented Programming
• Modular Design
• Secure Coding Practices
Every module should be reusable.
Every class should have a single responsibility.
Every function should have meaningful names.
Every file should contain appropriate comments.
Include exception handling everywhere appropriate.
Implement proper logging.
Implement validation.
Implement documentation.
Implement maintainable code.
==========================================================

OUTPUT REQUIREMENTS

==========================================================
Whenever generating code:
Generate complete files.
Never generate incomplete snippets.
Whenever generating a folder structure:
Generate the complete structure.
Whenever generating APIs:
Generate production-ready APIs.
Whenever generating HTML:
Generate complete pages.
Whenever generating CSS:
Generate complete styling.
Whenever generating JavaScript:
Generate complete scripts.
Whenever generating SQL:
Generate complete schemas.
Whenever generating documentation:
Generate complete documentation.
Whenever generating tests:
Generate complete tests.
Assume every generated file will immediately become part of the final project.
==========================================================
PROJECT OVERVIEW
==========================================================
Project Name:
CanaryGuard: Intelligent Endpoint Ransomware Detection & File Integrity Monitoring Dashboard
Project Domain:
Cybersecurity
Endpoint Detection & Response (EDR)
Behavioral Malware Detection
File Integrity Monitoring
Intrusion Detection System (IDS)
Web Application Development
Target Course:
Cybersecurity Mini Project
Project Duration:
Mini Project
==========================================================
PROJECT DESCRIPTION
==========================================================
Develop a complete Endpoint Detection & Response (EDR) application capable of detecting ransomware attacks through behavioral analysis rather than signature-based detection.
The system should continuously monitor the filesystem, deploy canary files, detect suspicious encryption activity using Shannon Entropy, identify malicious processes, automatically quarantine threats, log every incident, and display everything through a professional real-time web dashboard.
The final product should resemble a lightweight enterprise-grade security solution suitable for academic demonstration and GitHub publication.
==========================================================
PROJECT OBJECTIVES
==========================================================
The project should:
• Detect ransomware before large-scale encryption occurs.
• Monitor filesystem events continuously.
• Deploy hidden canary files.
• Perform File Integrity Monitoring.
• Calculate Shannon Entropy on modified files.
• Detect abnormal encryption behaviour.
• Identify the responsible process.
• Automatically quarantine malicious processes.
• Store every incident in the database.
• Provide a professional real-time monitoring dashboard.
• Demonstrate practical Endpoint Detection & Response concepts.
==========================================================
PROBLEM STATEMENT
==========================================================
Traditional antivirus software depends on signatures.
Modern ransomware frequently bypasses signature-based detection using:
• Zero-Day Malware
• Obfuscation
• Packing
• Polymorphism
• Encryption
This project must instead detect ransomware using behavioural analysis including:
• File access behaviour
• File integrity monitoring
• Entropy analysis
• Canary file monitoring
• Process behaviour
==========================================================
CORE FEATURES
==========================================================
Implement ALL of the following.
----------------------------------------------------------
1. CANARY FILE DEPLOYMENT
----------------------------------------------------------
Automatically generate realistic decoy files including:
Confidential_Report.docx
Payroll.xlsx
Employee_Database.pdf
Financial_Records.xlsx
Annual_Report.docx
Passwords.pdf
Project_Plan.docx
Contracts.pdf
Features:
• Automatic deployment
• Hidden attributes where supported
• Metadata tracking
• Database registration
• Automatic redeployment
----------------------------------------------------------
2. FILE SYSTEM MONITORING
----------------------------------------------------------
Continuously monitor folders using watchdog.
Detect:
File Created
File Modified
File Deleted
File Renamed
File Moved
Permission Changes
Canary Access
Canary Deletion
Canary Rename
Rapid File Changes
Bulk Encryption Activity
----------------------------------------------------------
3. FILE INTEGRITY MONITORING
----------------------------------------------------------
Track:
File Hash
Last Modified Time
Owner
Size
Extension
Permissions
Maintain integrity history.
Log every modification.
----------------------------------------------------------
4. SHANNON ENTROPY ENGINE
----------------------------------------------------------
Whenever a monitored file changes:
Read the file.
Calculate byte frequencies.
Compute Shannon Entropy.
Compare against configurable threshold.
Generate threat score.
Log results.
Store entropy history.
----------------------------------------------------------
5. RANSOMWARE DETECTION ENGINE
----------------------------------------------------------
Combine multiple detection mechanisms.
Canary Trigger
High Entropy
Rapid File Modifications
Mass Rename Operations
Mass Delete Operations
Bulk Encryption
Process Behaviour
Generate a confidence score.
Reduce false positives.
Generate incident reports.
----------------------------------------------------------
6. PROCESS IDENTIFICATION
----------------------------------------------------------
Using psutil identify:
PID
Parent PID
Executable Path
Command Line
Username
CPU Usage
Memory Usage
Running Time
Child Processes
Executable Name
Status
----------------------------------------------------------
7. PROCESS QUARANTINE
----------------------------------------------------------
When a threat is detected:
Freeze process where supported.
Terminate process.
Terminate child processes.
Log quarantine.
Generate alert.
Broadcast dashboard update.
----------------------------------------------------------
8. INCIDENT MANAGEMENT
----------------------------------------------------------
Maintain complete incident history.
Each incident stores:
Timestamp
Threat Level
File Path
Canary Status
Entropy
PID
Process Name
Executable
Action Taken
Status
Recovery Notes
----------------------------------------------------------
9. REAL-TIME ALERTING
----------------------------------------------------------
Generate alerts for:
Canary Trigger
High Entropy
Killed Process
Quarantine
Monitoring Started
Monitoring Stopped
Database Errors
Permission Errors
Dashboard Connection
----------------------------------------------------------
10. REST API
----------------------------------------------------------
Create complete REST APIs.
GET
/api/status
/api/incidents
/api/processes
/api/statistics
/api/canaries
/api/settings

POST
/api/start-monitor
/api/stop-monitor
/api/deploy-canaries
/api/quarantine
/api/settings
DELETE
/api/canaries
/api/incidents
Return proper JSON responses.
Implement validation.
Implement error handling.
==========================================================
NON-FUNCTIONAL REQUIREMENTS
==========================================================
The project must be:
Modular
Secure
Responsive
Scalable
Maintainable
Readable
Professional
Production-quality
Well documented
Easy to demonstrate
Easy to install
Suitable for GitHub publication
Suitable for academic evaluation
==========================================================
SOFTWARE ARCHITECTURE
==========================================================
The application shall follow a modular layered architecture.
The architecture should separate the project into independent components to maximize maintainability, scalability, readability and security.
Architecture Layers:
1. Presentation Layer
2. API Layer
3. Business Logic Layer
4. Detection Engine
5. Process Management Layer
6. Database Layer
7. Utility Layer
Every layer must communicate only through well-defined interfaces.
Avoid tightly coupled modules.
==========================================================
INTERNAL PROJECT STRUCTURE
==========================================================
Inside the existing CanaryGuard folder automatically create an organized structure similar to the following whenever required.
CanaryGuard/

│
├── app.py
├── run.py
├── config.py
├── requirements.txt
├── README.md
├── .gitignore
├── .env.example
│
├── app/
│   ├── __init__.py
│   ├── routes/
│   ├── models/
│   ├── services/
│   ├── controllers/
│   ├── middleware/
│   ├── utilities/
│   ├── database/
│   ├── monitoring/
│   ├── entropy/
│   ├── canary/
│   ├── quarantine/
│   ├── websocket/
│   ├── logging/
│   ├── scheduler/
│   ├── alerts/
│   ├── configuration/
│   └── security/
│
├── templates/
│
├── static/
│   ├── css/
│   ├── js/
│   ├── images/
│   ├── icons/
│   └── fonts/
│
├── database/
│
├── logs/
│
├── reports/
│
├── docs/
│
├── screenshots/
│
├── tests/
│
├── scripts/
│
└── backups/
Create additional folders whenever they improve the project.
==========================================================
DATABASE DESIGN
==========================================================
Use SQLite together with SQLAlchemy ORM.
Automatically create all required tables.
Suggested tables include:
Users
Incidents
CanaryFiles
EntropyLogs
ProcessLogs
ThreatStatistics
QuarantineHistory
SystemSettings
ActivityLogs
DashboardEvents
SecurityPolicies
MonitoredFolders
Alerts
Every table should include:
Primary Key
Created Timestamp
Updated Timestamp
Appropriate Foreign Keys
Indexes where beneficial
Data validation
==========================================================
LOGGING SYSTEM
==========================================================
Implement structured logging.
Automatically create:
logs/system.log
logs/security.log
logs/errors.log
logs/quarantine.log
logs/entropy.log
logs/api.log
Support:
Log rotation
Timestamped entries
Log levels
Error stack traces
==========================================================
REAL-TIME DASHBOARD
==========================================================
Build a modern professional dashboard.
Preferred design:
Dark Theme
Cybersecurity-inspired interface
Responsive layout
Professional typography
Modern cards
Interactive tables
Animated statistics
Live updates
Dashboard pages should include:
Dashboard
Live Threat Feed
Incidents
Processes
Canary Management
Monitored Folders
System Statistics
Configuration
Logs Viewer
About
==========================================================
DASHBOARD COMPONENTS
==========================================================
Dashboard cards:
Current Status
Monitoring Status
Threat Level
Protected Files
Canary Count
Processes Terminated
Entropy Events
Incidents Today
Charts:
Threat Timeline
Entropy Distribution
Process Activity
Incident Frequency
Quarantine Statistics
File Activity
Recent Alerts
Recent Logs
==========================================================
WEB TECHNOLOGIES
==========================================================
Backend:
Python 3.10+
Flask
Flask-SocketIO
Flask-SQLAlchemy
watchdog
psutil
SQLite
threading
logging
math
hashlib
os
pathlib
Frontend:
HTML5
TailwindCSS
JavaScript ES6
Socket.IO Client
Fetch API
Responsive Design
==========================================================
REST API REQUIREMENTS
==========================================================
Implement complete REST APIs.
Each endpoint must include:
Validation
Status Codes
JSON Responses
Logging
Exception Handling
Authentication-ready architecture
Future extensibility
==========================================================
WEBSOCKET REQUIREMENTS
==========================================================
Use Flask-SocketIO.
Broadcast:
Threat Alerts
Process Kills
Canary Triggers
Monitoring Status
Entropy Results
Dashboard Updates
System Notifications
Reconnect automatically if the client disconnects.
==========================================================
CONFIGURATION SYSTEM
==========================================================
Create a configurable settings system.
Settings should include:
Entropy Threshold
Monitoring Enable/Disable
Automatic Quarantine
Protected Folders
Canary Deployment
Dashboard Refresh
Log Level
Alert Settings
Persist all settings in SQLite.
==========================================================
SECURITY REQUIREMENTS
==========================================================
Implement secure coding practices.
Validate all inputs.
Sanitize user input.
Prevent crashes.
Handle permission errors.
Gracefully recover from failures.
Avoid unnecessary privileges.
Log all security-relevant events.
Implement comprehensive exception handling.
==========================================================
PERFORMANCE REQUIREMENTS
==========================================================
The application should:
Use background threads where appropriate.
Avoid blocking the UI.
Minimize CPU usage.
Minimize memory usage.
Avoid duplicate calculations.
Reuse objects where practical.
Optimize database queries.
Use efficient filesystem monitoring.
==========================================================
CODE ORGANIZATION
==========================================================
Separate:
Models
Routes
Controllers
Services
Utilities
Database
Monitoring Engine
Entropy Engine
Canary Engine
Quarantine Engine
Configuration
Templates
Static Assets
Testing
Documentation
Every module should have a clear responsibility.
Avoid monolithic files.
Split large files into reusable components whenever appropriate.
==========================================================
AUTONOMOUS DEVELOPMENT WORKFLOW
==========================================================
Build the project as if you are a professional software development team delivering a production-ready application.
Work sequentially through the entire project lifecycle without asking for additional instructions.
Suggested workflow:
Phase 1
- Analyze the project requirements.
- Design the architecture.
- Plan the folder structure.
- Create all required directories.

Phase 2
- Generate configuration files.
- Generate dependency files.
- Create the database models.
- Initialize the Flask application.

Phase 3
- Implement the monitoring engine.
- Implement the canary deployment engine.
- Implement the entropy engine.
- Implement the ransomware detection engine.
- Implement process identification.
- Implement process quarantine.

Phase 4
- Build REST APIs.
- Build WebSocket communication.
- Connect backend modules.

Phase 5
- Build the frontend.
- Create dashboard pages.
- Add real-time updates.
- Implement charts and tables.

Phase 6
- Implement logging.
- Implement settings.
- Implement testing.
- Optimize performance.
- Refactor code where appropriate.

Phase 7
- Generate documentation.
- Generate README.
- Generate setup guide.
- Generate deployment guide.
- Generate API documentation.
- Final verification.
Proceed automatically from one phase to the next.
Never wait for confirmation.
==========================================================
CODE GENERATION RULES
==========================================================
Generate complete source files.
Do not generate isolated snippets unless specifically requested.
Every generated file should be immediately usable.
Do not leave TODOs where a complete implementation is practical.
Do not intentionally omit important logic.
Implement realistic business logic.
Use meaningful names for:
Classes
Functions
Variables
Modules
Packages
Keep the code clean and readable.
==========================================================
OBJECT ORIENTED DESIGN
==========================================================
Use Object-Oriented Programming wherever appropriate.
Apply SOLID principles.
Each class should have a single responsibility.
Avoid large monolithic classes.
Favor composition over inheritance where appropriate.
Create reusable utility classes.
Separate business logic from routes.
==========================================================
CODING STANDARDS
==========================================================
Follow Python best practices.
Use:
Type hints
Docstrings
Meaningful comments
Exception handling
Logging
Input validation
Avoid duplicate code.
Avoid magic numbers.
Keep functions focused.
Organize imports properly.
Follow PEP 8 conventions.
==========================================================
ERROR HANDLING
==========================================================
Handle all expected exceptions gracefully.
Examples include:
Missing files
Permission denied
Database failures
Network failures
Invalid configuration
Missing directories
Corrupted data
Filesystem errors
Unexpected process termination
Always log exceptions.
Never allow the application to crash unnecessarily.
==========================================================
TESTING REQUIREMENTS
==========================================================
Automatically generate a comprehensive test suite.
Include:
Unit Tests
Integration Tests
API Tests
Database Tests
Monitoring Tests
Entropy Calculation Tests
Canary Deployment Tests
Quarantine Tests
Dashboard Tests
Error Handling Tests
Use Python testing frameworks where appropriate.
==========================================================
DOCUMENTATION
==========================================================
Generate professional documentation.
Include:
README.md
Installation Guide
User Guide
Developer Guide
Architecture Documentation
Database Documentation
API Documentation
Testing Guide
Deployment Guide
Future Enhancements
Troubleshooting Guide
Project Report
The documentation should be suitable for GitHub and academic submission.
==========================================================
DEPENDENCY MANAGEMENT
==========================================================
Automatically generate:
requirements.txt
Include every required package.
Use stable package versions where appropriate.
If additional packages become necessary during development, update the dependency list automatically.
==========================================================
GIT PROJECT PREPARATION
==========================================================
Prepare the project for Git.
Automatically generate:
.gitignore
README.md
Project structure documentation
Example environment configuration (.env.example)
Ensure the repository is clean and professional.
==========================================================
USER INTERFACE REQUIREMENTS
==========================================================
Create a modern cybersecurity-themed dashboard.
Preferred characteristics:
Dark theme
Responsive design
Professional typography
Clean layout
Interactive tables
Live status indicators
Animated statistics
Professional icons
Well-organized navigation
The dashboard should look polished and presentation-ready.
==========================================================
SECURITY BEST PRACTICES
==========================================================
Apply secure coding practices throughout the project.
Validate all user input.
Avoid unsafe filesystem operations.
Prevent common vulnerabilities where applicable.
Use safe database interactions through SQLAlchemy ORM.
Protect against accidental data loss.
Implement proper access validation where appropriate.
==========================================================
PROJECT QUALITY GOALS
==========================================================
The final project should be:
Professional
Modular
Maintainable
Readable
Secure
Scalable
Efficient
Well documented
Easy to understand
Easy to extend
Suitable for demonstration
Suitable for GitHub publication
Suitable for academic evaluation
==========================================================
AUTONOMOUS DECISION MAKING
==========================================================
Whenever multiple implementation choices exist:
Select the solution that provides:
Better maintainability
Better scalability
Better security
Better performance
Better readability
Better modularity
Never ask the user to choose between alternatives unless it is impossible to continue without external information.
==========================================================
FINAL DELIVERABLES
==========================================================
The completed project should include, at minimum:
Complete project folder structure
Backend source code
Frontend source code
Database models
SQLite database
REST APIs
WebSocket implementation
Canary deployment engine
Filesystem monitoring engine
Shannon entropy engine
Behavioral ransomware detection engine
Process identification module
Process quarantine module
Incident logging
Dashboard
Configuration system
Logging system
Tests
Documentation
README
Setup guide
API documentation
Architecture documentation
Deployment guide
Example configuration
Git-ready project structure
Any additional helper modules necessary for a production-quality implementation.
==========================================================
FINAL EXECUTION POLICY
==========================================================
Continue building until every major feature described in this prompt has been implemented.
Do not stop after creating only the project structure.
Do not stop after creating only the backend.
Do not stop after creating only the frontend.
Do not stop after creating only the database.
Build every component required for the complete application.
If additional files, folders, classes, modules, templates, configurations, or documentation are needed, create them automatically within the existing CanaryGuard project directory.
Never create a second root folder.
Never ask unnecessary questions.
Never request confirmation before proceeding.
Use professional judgment and industry best practices whenever details are unspecified.
Generate production-ready code and documentation wherever practical.
Treat this prompt as the complete project specification and continue working autonomously until the requested implementation is complete.
