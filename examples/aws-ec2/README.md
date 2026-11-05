# AWS EC2

EC2 instances sit behind NAT, so pass the public address explicitly
(Elastic IP recommended); auto-detection would find the private address.

```sh
vwitch cloud-init --endpoint 203.0.113.10 --allow-direct > user-data.yaml

aws ec2 run-instances \
  --image-id <debian-13-ami> --instance-type t4g.micro \
  --key-name my-key --security-group-ids <sg> \
  --user-data file://user-data.yaml
```

The security group needs inbound UDP 51845. Disabling the source/destination
check is not required, because client traffic is masqueraded.
