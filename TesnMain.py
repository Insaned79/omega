from flask_testing import TestCase
from main import app, connect_db
import unittest


class TestRegisterRoute(TestCase):
    def create_app(self):
        return app

    def test_register_route_with_successful_registration(self):
        response = self.client.post('/register',
                                    data={'username': 'testuser', 'password': 'Passw0rd!', 'password2': 'Passw0rd!'})
        self.assertRedirects(response, '/login')

    def test_register_route_with_username_already_taken(self):
        self.client.post('/register', data={'username': 'testuser', 'password': 'Passw0rd!', 'password2': 'Passw0rd!'})
        response = self.client.post('/register',
                                    data={'username': 'testuser', 'password': 'Passw0rd!', 'password2': 'Passw0rd!'})
        self.assertIn(b'Error: This username is already taken.', response.data)

    def test_register_route_with_passwords_not_matching(self):
        response = self.client.post('/register',
                                    data={'username': 'testuser', 'password': 'Passw0rd!', 'password2': 'passwor'})
        self.assertIn(b'Error: Passwords do not match.', response.data)

    def test_register_route_with_weak_password(self):
        response = self.client.post('/register',
                                    data={'username': 'testuser', 'password': 'password', 'password2': 'password'})
        self.assertIn(b'Error: Password is not strong enough.', response.data)

    def tearDown(self):
        # Connect to the database
        conn = connect_db()
        c = conn.cursor()
        # Delete the test user from the database
        c.execute("DELETE FROM users WHERE username = 'testuser'")
        conn.commit()
        conn.close()


class TestLoginRoute(TestCase):
    def create_app(self):
        return app

    def test_login_route_with_successful_login(self):
        # First, create a test user to log in with
        self.client.post('/register', data={'username': 'testuser', 'password': 'Passw0rd!', 'password2': 'Passw0rd!'})

        response = self.client.post('/login', data={'username': 'testuser', 'password': 'Passw0rd!'})
        self.assertRedirects(response, '/')

    def test_login_route_with_user_not_found(self):
        response = self.client.post('/login', data={'username': 'testuser', 'password': 'password'})
        self.assertIn(b'Error: User not found.', response.data)

    def test_login_route_with_incorrect_password(self):
        self.client.post('/register', data={'username': 'testuser', 'password': 'Passw0rd!', 'password2': 'Passw0rd!'})

        response = self.client.post('/login', data={'username': 'testuser', 'password': 'incorrectpassword'})
        self.assertIn(b'Error: Incorrect password.', response.data)

    def test_login_route_with_banned_account(self):
        # First, create a test user to log in with
        self.client.post('/register', data={'username': 'testuser', 'password': 'Passw0rd!', 'password2': 'Passw0rd!'})

        # Ban the test user
        conn = connect_db()
        c = conn.cursor()
        c.execute("UPDATE users SET access_level=0 WHERE username=?", ('testuser',))
        conn.commit()
        conn.close()

        response = self.client.post('/login', data={'username': 'testuser', 'password': 'Passw0rd!'})
        self.assertIn(b'Error: Your account is banned.', response.data)

    def tearDown(self):
        # Connect to the database
        conn = connect_db()
        c = conn.cursor()
        # Delete the test user from the database
        c.execute("DELETE FROM users WHERE username = 'testuser'")
        conn.commit()
        conn.close()


if __name__ == '__main__':
    unittest.main()
