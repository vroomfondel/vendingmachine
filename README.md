# FastAPI :: vendingmachine

[![black-lint and mypy static type check](https://github.com/vroomfondel/vendingmachine/actions/workflows/blacknmypy.yml/badge.svg?branch=main)](https://github.com/vroomfondel/vendingmachine/actions/workflows/blacknmypy.yml)
[![run pytests](https://github.com/vroomfondel/vendingmachine/actions/workflows/pytests.yml/badge.svg?branch=main)](https://github.com/vroomfondel/vendingmachine/actions/workflows/pytests.yml)
[![BuildAndPushMultiarch](https://github.com/vroomfondel/vendingmachine/actions/workflows/buildmultiarchandpush.yml/badge.svg?branch=main)](https://github.com/vroomfondel/vendingmachine/actions/workflows/buildmultiarchandpush.yml)

API-design for a vending machine, allowing users with a “seller” role to add, update or remove products, while users with a “buyer” 
role can deposit coins into the machine and make purchases. The vending machine only accepts 5, 10, 20, 50 and 100 cent coins.

- Used this as a basis for a fastapi-demo-app using OAUTH2-authorization with HS256 and/or RS256 signed JWT tokens with the 
possibiility of rotating keys and (in case of RS256) edge-verification of the JWT with only possessing the public-key.
- Used this a starting point to use deta ( https://web.deta.sh ) for demo-purposes (currently API is live here: https://6v42p6.deta.dev/ )
- Docker image (amd+arm64): https://hub.docker.com/repository/docker/vroofoo/vendingmachine 

## Build/CI (via github actions)
- linting (using black)
- mypy
- pytests
- building multiarch-docker-image (amd64+arm64("aarch64")) => quite handy for me since my homelab is running k3s on a
  mix of amd64 and aarch64 

## Tried to adhere:
- GET	A GET method (or GET request) is used to retrieve a representation of a resource. It should be used SOLELY for retrieving data and should not alter.
- PUT	A PUT method (or PUT request) is used to update a resource. For instance, if you know that a blog post resides at http://www.example.com/blogs/123, you can update this specific post
- by using the PUT method to put a new resource representation of the post.
- POST	A POST method (or POST request) is used to create a resource. For instance, when you want to add a new blog post but have no idea
- where to store it, you can use the POST method to post it to a URL and let the server decide the URL.
- PATCH	A PATCH method (or PATCH request) is used to modify a resource. It contains the changes to the resource, instead of the complete resource.
- DELETE	A DELETE method (or DELETE request) is used to delete a resource identified by a URI.


## Usage (in very short short short)
```bash
$ make

install
	install requirements

isort
	make isort import corrections

lint
	make linter check with black

tcheck
	make static type checks with mypy

tests
	Launch tests

prepare
	Launch tests and commit-checks

commit-checks
	run pre-commit checks on all files

start 
	start app in uvicorn - listening on port 18889

docker-build 
	build docker-image

docker-run 
	run in (locally) built docker-image
	
docker-run-dh 
	run LATEST image from DockerHub
		
```
## InitialData
- To create initial data (using ["faker"](https://faker.readthedocs.io/en/master/) btw.) i.e. fake-users, fake-products and some keys for HS256 and RS256, call:
- in vendingmachine.utils.datapersintence ```"__main__"``` resp. ```asyncio.run(vendingmachine.utils.datapersintence.generate_pseudo_data_to_db())```  
