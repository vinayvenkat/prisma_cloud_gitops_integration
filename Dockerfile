FROM alpine:3.8
RUN apk --no-cache add ca-certificates
RUN echo "$PWD"
RUN ls
WORKDIR /bin/
COPY bin/pansecadapter .
WORKDIR /home/
COPY pansecurityadapter/license.txt . 
ENTRYPOINT [ "/bin/pansecadapter" ]
CMD [ "9693" ]
EXPOSE 9693 
