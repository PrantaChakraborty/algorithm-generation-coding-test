# User Authentication 
An authentication api task for Algorithm Generation

# Prerequisites
   1. Python 3.x
   2. virtualenv (recommended) https://www.freecodecamp.org/news/how-to-setup-virtual-environments-in-python/
   3. PostgreSQL for windows https://www.postgresqltutorial.com/postgresql-getting-started/install-postgresql/
      for ubuntu https://linuxhint.com/install-and-setup-postgresql-database-ubuntu-22-04/
## Installation
1. Clone the repository
   https://github.com/PrantaChakraborty/algorithm-generation-coding-test.git
2. Create database.

   3. After clone the repository follow the steps 
      ```bash
         # goto the project folder
         cd algorithm-generation-coding-test
   
         # create an .env file and copy all from env.example to .env
         touch .env
         cp env.example .env
   
         # change the database settings with newly created database & credentials 
      
   
         # create a virtual environment
         virturalenv venv
      
         # active the virtual environment
         source vevn/bin/activate
   
         # make migrations & migrate
         python mange.py makemigrations
         python manage.py migrate
   
         # create a superuser
         python manage.py createsuperuser
      
         # after creating superuser run the development server
         python manage.py runserver
   
   
      
      
      ```

API postman collection are in this link https://documenter.getpostman.com/view/13941423/2s8ZDa11hR
