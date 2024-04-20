.DEFAULT_GOAL:=help

COMPOSE_PREFIX_CMD := COMPOSE_DOCKER_CLI_BUILD=1
COMPOSE_ALL_FILES := -f docker-compose.yml
SERVICES          := db web redis celery celery-beat


.PHONY: up build username down stop restart rm logs


up:				## Build and start all services.
	${COMPOSE_PREFIX_CMD} docker-compose ${COMPOSE_ALL_FILES} up -d --build ${SERVICES}

build:			## Build all services.
	${COMPOSE_PREFIX_CMD} docker-compose ${COMPOSE_ALL_FILES} build ${SERVICES}

superuser:		## Generate Username (Use only after make up).
	${COMPOSE_PREFIX_CMD} docker-compose ${COMPOSE_ALL_FILES} exec web python3 manage.py createsuperuser

down:			## Down all services.
	${COMPOSE_PREFIX_CMD} docker-compose ${COMPOSE_ALL_FILES} down

stop:			## Stop all services.
	${COMPOSE_PREFIX_CMD} docker-compose ${COMPOSE_ALL_FILES} stop ${SERVICES}

restart:		## Restart all services.
	${COMPOSE_PREFIX_CMD} docker-compose ${COMPOSE_ALL_FILES} restart ${SERVICES}

rm:				## Remove all services containers.
	${COMPOSE_PREFIX_CMD} docker-compose $(COMPOSE_ALL_FILES) rm -f ${SERVICES}

logs:			## Tail all logs with -n 1000.
	${COMPOSE_PREFIX_CMD} docker-compose $(COMPOSE_ALL_FILES) logs --follow --tail=1000 ${SERVICES}

images:			## Show all Docker images.
	${COMPOSE_PREFIX_CMD} docker-compose $(COMPOSE_ALL_FILES) images ${SERVICES}

prune:			## Remove containers and delete volume data.
	@make stop && make rm && docker volume prune -f
