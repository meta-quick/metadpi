mdpi:
	CGO_ENABLED=1 go build -o mdpi main.go

clean:
	rm -rf mdpi