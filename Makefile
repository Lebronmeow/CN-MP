.PHONY: start stop restart mode-a mode-b mode-custom verify status test

start:
	python lab.py start

stop:
	python lab.py stop

restart:
	python lab.py stop
	python lab.py start

mode-a:
	python lab.py mode-a

mode-b:
	python lab.py mode-b

mode-custom:
	python lab.py mode-custom

status:
	python lab.py status

verify:
	python lab.py verify

test:
	npm test
