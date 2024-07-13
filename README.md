
# DonorApp (name might change)

## Video Demo: **TODO**

## Description

DonorApp is a purpose-built web application aimed at coordinating donations effectively among orphanages, old age homes, and other legitimate organizations or individuals in need. It hopes to addresses the common issue in many cities where multiple NGOs often duplicate efforts by providing the same resources to the same recipients due to inadequate communication. This app aims to solve this problem by establishing a streamlined communication platform. It should ensure that essential donations such as food, water, and other necessities are managed efficiently, minimizing wastage and maximizing impact.

## Development Details

- Developed using Visual Studio Code.
- Built with Python primarily using the Flask framework, alongside HTML, CSS, and JavaScript for frontend interactions.

## Features

- **Registration and Login:** Users register under three types and login after admin authorization.
- **Request Management:** Recipients create and manage donation requests displayed on the home page.
- **Donations:** Donors and Donor Orgs contribute to requests; self-donations are restricted.
- **Donation History:** Users can view their donation histories.
- **Admin Control:** Admins manage user authorizations and oversee app operations.
- **Theme Customization:** Users can switch between light and dark modes.
- **Profile Management:** Users can update email, username, and password.

## Technology Stack

- **Frontend:** HTML, CSS, JavaScript
- **Backend:** Python, Flask with Jinja templating, AJAX

## Setup Instructions

1. Clone the repository.
2. Install dependencies (`pip install -r requirements.txt` for Flask).
3. Configure your Flask application settings.
4. Run the Flask development server to start the application.

## File Structure and Description

### Python Files

- **app.py:** App factory for app initialization.
- **tables.py** Runs the base initialistion code to create the tables

### HTML Files

- **admin.html:** Admin dashboard for user authorization management. (**ACCESSIBLE TO ADMINS ONLY**)
- **history.html:** Display of user post history.
- **index.html:** Homepage displaying donation requests.
- **layout.html:** Base layout template for consistent UI.
- **login.html:** Login page which allows users after user is authenticated.
- **post.html:** Template for creating new donation requests.
- **profile.html:** User profile page for managing personal information. Also displays users donation history and shows user their own post history. Others can view base profile of a person
- **register.html:** Registration page for new users.
- **requests.html:** Page displaying all donation requests. Users can filter and search through requests with live changes.
- **settings.html:** User settings page for theme customization.
- **users.html:** Admin page listing all users for management. (**ACCESSIBLE TO ADMINS ONLY**)

## Code Snippets

Here's how donation requests are handled in `app.py`:

```python
#CODE TEMPLATE 1 HERE !!!
```

## Screenshots

![Screenshot 1](/path/to/screenshot1.png)
*Caption for Screenshot 1.*

![Screenshot 2](/path/to/screenshot2.png)
*Caption for Screenshot 2.*

## How to Use

- Open the application in your web browser.
- Register and log in based on user type and admin authorization.
- Make a donation request if a donor user.
- Manage donation requests and contributions.
- View donation history and adjust profile settings.
- Customize interface theme to light or dark mode based on preference.

## Contributing

- Contributions are welcome! Fork the repository, create a branch, and submit a pull request.

### Notes

- Replace `/path/to/screenshot1.png` and `/path/to/screenshot2.png` with the actual paths to your screenshots.
