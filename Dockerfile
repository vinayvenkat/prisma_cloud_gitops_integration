FROM alpine:3.8
RUN apk --no-cache add ca-certificates
RUN echo "$PWD"
RUN ls
COPY ./pansecadapter /bin
COPY ./license.txt /home
WORKDIR /bin/
RUN ls
#COPY bin/pansecadapter .
#COPY bin/pansecadapter .
WORKDIR /home/
#COPY pansecurityadapter/license.txt . 
RUN ls
RUN ls -l
ENTRYPOINT [ "/bin/pansecadapter" ]
CMD [ "9693" ]
EXPOSE 9693 
