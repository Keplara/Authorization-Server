# Auth-Service

# To configure the application follow the steps below.

<h3>In order to be able to use the google APIs we need to set up the user to use the service account. A service account key is dangerous to hand around so using gcloud we can impersonate via the command line and be able to run the application locally.</h3>

</b>

<h3>Go to this link <a href="https://cloud.google.com/sdk/docs/install"> https://cloud.google.com/sdk/docs/install
</a> to be able to set up the command line tool GCLI</h3>

</b>

<h3> Once we access the command line we can log in as our user.</h3>
<h3> Next we want to log in as our user which may be myusername@keplara.com </h3>
<h3> Select the project Keplara </h3>
<h3> Next we will set the default login which should be your account <code>gcloud auth application-default login</code> </h3>
<h3>Last we want impersonate the service account as if we were the application.  <code>gcloud auth application-default login --impersonate-service-account service-account-to-impersonate@someemail
</code>. More info located here <a href="https://cloud.google.com/docs/authentication/provide-credentials-adc#local-dev"> more info </a> </h3>

<h3> Set your configurations like this for vs code launch.json <h3> <h4>You want to use the launch.json so you don't have to deal with setting the envs all the time.</h4>
<code>
    {
      "version": "0.2.0",
        "configurations": [
            {
            "type": "java",
            "name": "Current File",
            "request": "launch",
            "mainClass": "${file}"
            },
            {
            "type": "java",
            "name": "Gradle Spring Boot Application",
            "request": "launch",
            "mainClass": "${file}",
            "projectName": "keplara",
            "preLaunchTask": "gradle: bootRun",
            "args": [
                "--spring.profiles.active=dev"
            ],
            "env": {
                "GOOGLE_APPLICATION_CREDENTIALS": "C:\\Users\\grant\\AppData\\Roaming\\gcloud\\application_default_credentials.json",
            },
            "presentation": {
                "clear": true,
                "panel": "dedicated"
            }
         }
        ]
    }
</code>

// the key would be for the auto deployment where users do not have access to the key