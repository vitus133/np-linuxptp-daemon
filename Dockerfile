FROM golang:1.23.5 AS builder
WORKDIR /go/src/github.com/k8snetworkplumbingwg/linuxptp-daemon
COPY . .
RUN make clean && make

FROM quay.io/centos/centos:stream9

COPY extra/linuxptp-4.4-1.el9_2.test72468.1.x86_64.rpm /
RUN yum -y update && yum -y update glibc && yum --setopt=skip_missing_names_on_install=False -y install /linuxptp-4.4-1.el9_2.test72468.1.x86_64.rpm ethtool hwdata synce4l && yum clean all && \
	rm /linuxptp-4.4-1.el9_2.test72468.1.x86_64.rpm


RUN yum install -y gpsd-minimal
RUN yum install -y gpsd-minimal-clients

# Create symlinks for executables to match references
RUN ln -s /usr/bin/gpspipe /usr/local/bin/gpspipe
RUN ln -s /usr/sbin/gpsd /usr/local/sbin/gpsd
RUN ln -s /usr/bin/ubxtool /usr/local/bin/ubxtool


COPY --from=builder /go/src/github.com/k8snetworkplumbingwg/linuxptp-daemon/bin/ptp /usr/local/bin/

CMD ["/usr/local/bin/ptp"]