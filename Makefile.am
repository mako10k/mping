SUBDIRS = src
EXTRA_DIST = docker/Dockerfile \
	     debian/changelog \
	     debian/compat \
	     debian/control \
	     debian/postinst \
	     debian/rules \
	     debian/dput.cf

docker-build: docker/Dockerfile docker/@PACKAGE@-@VERSION@.tar.gz
	docker rmi @PACKAGE@-build:latest || true
	sudo docker build --rm --force-rm --tag=@PACKAGE@-build docker
	docker kill @PACKAGE@-build || true
	docker run -dit --rm --name=@PACKAGE@-build @PACKAGE@-build
	docker cp @PACKAGE@-build:/root/sync/ ./
	docker cp @PACKAGE@-build:/root/@PACKAGE@-@VERSION@.tar.gz sync/stretch/@PACKAGE@_@VERSION@.orig.tar.gz
	docker kill @PACKAGE@-build

docker/%.tar.gz: %.tar.gz
	cp $< $@

@PACKAGE@-@VERSION@.tar.gz: dist $(EXTRA_DIST)
