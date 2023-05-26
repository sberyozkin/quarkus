# Quarkus RP OIDC Certification

## How to test

Start a certification endpoint in the `certification-endpoint` folder with `mvn quarkus:dev`.

Go to `https://www.certification.openid.net/plan-detail.html?plan=RPUGzpD20SQYS`.

Run tests one by one as documented. Go to `http://localhost:8080/oidc` to have the current running test in a `Waiting` state completed and transitioned to a `Finished` state. Repeat for every listed test at `https://www.certification.openid.net/plan-detail.html?plan=RPUGzpD20SQYS`.

## Basic Profile ResponseMode Query

https://www.certification.openid.net/plan-detail.html?plan=RPUGzpD20SQYS&public=true
