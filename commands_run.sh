# Install kubectl
sudo curl --silent --location -o /usr/local/bin/kubectl \
  https://amazon-eks.s3.us-west-2.amazonaws.com/1.17.11/2020-09-18/bin/linux/amd64/kubectl

sudo chmod +x /usr/local/bin/kubectl

#Update awscli
Upgrade AWS CLI according to guidance in AWS documentation.

sudo pip install --upgrade awscli && hash -r

#Install jq, envsubst (from GNU gettext utilities) and bash-completion
sudo yum -y install jq gettext bash-completion moreutils

#Install yq for yaml processing
echo 'yq() {
  docker run --rm -i -v "${PWD}":/workdir mikefarah/yq "$@"
}' | tee -a ~/.bashrc && source ~/.bashrc

#Verify the binaries are in the path and executable
for command in kubectl jq envsubst aws; do
  which $command &>/dev/null && echo "$command in path" || echo "$command NOT FOUND"
done

#Enable kubectl bash_completion
kubectl completion bash >>~/.bash_completion
. /etc/profile.d/bash_completion.sh
. ~/.bash_completion

#set the AWS Load Balancer Controller version
echo 'export LBC_VERSION="v2.0.0"' >>~/.bash_profile
. ~/.bash_profile






# modify in console, instructions https://www.eksworkshop.com/020_prerequisites/iamrole/







#To ensure temporary credentials aren’t already in place we will also remove any existing credentials file:
rm -vf ${HOME}/.aws/credentials

export ACCOUNT_ID=$(aws sts get-caller-identity --output text --query Account)
export AWS_REGION=$(curl -s 169.254.169.254/latest/dynamic/instance-identity/document | jq -r '.region')
export AZS=($(aws ec2 describe-availability-zones --query 'AvailabilityZones[].ZoneName' --output text --region $AWS_REGION))

#Check if AWS_REGION is set to desired region

test -n "$AWS_REGION" && echo AWS_REGION is "$AWS_REGION" || echo AWS_REGION is not set

#Let’s save these into bash_profile
echo "export ACCOUNT_ID=${ACCOUNT_ID}" | tee -a ~/.bash_profile
echo "export AWS_REGION=${AWS_REGION}" | tee -a ~/.bash_profile
echo "export AZS=(${AZS[@]})" | tee -a ~/.bash_profile
aws configure set default.region ${AWS_REGION}
aws configure get default.region

#Validate the IAM role
#Use the GetCallerIdentity CLI command to validate that the Cloud9 IDE is using the correct IAM role.
aws sts get-caller-identity --query Arn | grep eksworkshop-admin -q && echo "IAM role valid" || echo "IAM role NOT valid"


#Create a CMK for the EKS cluster to use when encrypting your Kubernetes secrets:
aws kms create-alias --alias-name alias/eksworkshop --target-key-id $(aws kms create-key --query KeyMetadata.Arn --output text)

#Let’s retrieve the ARN of the CMK to input into the create cluster command.
export MASTER_ARN=$(aws kms describe-key --key-id alias/eksworkshop --query KeyMetadata.Arn --output text)

#We set the MASTER_ARN environment variable to make it easier to refer to the KMS key later.
#Now, let’s save the MASTER_ARN environment variable into the bash_profile
echo "export MASTER_ARN=${MASTER_ARN}" | tee -a ~/.bash_profile


#For this module, we need to download the eksctl binary:
curl --silent --location "https://github.com/weaveworks/eksctl/releases/download/0.44.0/eksctl_Linux_amd64.tar.gz" | tar xz -C /tmp

sudo mv -v /tmp/eksctl /usr/local/bin
#Confirm the eksctl command works:
eksctl version

#Enable eksctl bash-completion
eksctl completion bash >> ~/.bash_completion
. /etc/profile.d/bash_completion.sh
. ~/.bash_completion


cat << EOF > eksworkshop.yaml
---
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig

metadata:
  name: eksworkshop-eksctl
  region: ${AWS_REGION}
  version: "1.17"

availabilityZones: ["${AZS[0]}", "${AZS[1]}", "${AZS[2]}"]

managedNodeGroups:
- name: nodegroup
  desiredCapacity: 3
  instanceType: t3.small
  ssh:
    enableSsm: true

# To enable all of the control plane logs, uncomment below:
# cloudWatch:
#  clusterLogging:
#    enableTypes: ["*"]

secretsEncryption:
  keyARN: ${MASTER_ARN}
EOF

# long run
eksctl create cluster -f eksworkshop.yaml

#Test the cluster:
#Confirm your nodes:
kubectl get nodes # if we see our 3 nodes, we know we have authenticated correctly

#Export the Worker Role Name for use throughout the workshop:
STACK_NAME=$(eksctl get nodegroup --cluster eksworkshop-eksctl -o json | jq -r '.[].StackName')
ROLE_NAME=$(aws cloudformation describe-stack-resources --stack-name $STACK_NAME | jq -r '.StackResources[] | select(.ResourceType=="AWS::IAM::Role") | .PhysicalResourceId')
echo "export ROLE_NAME=${ROLE_NAME}" | tee -a ~/.bash_profile


#Increase cluster size
#We need more resources for completing the Kubeflow chapter of the EKS Workshop. First, we’ll increase the size of our cluster to 6 nodes
export NODEGROUP_NAME=$(eksctl get nodegroups --cluster eksworkshop-eksctl -o json | jq -r '.[0].Name')
eksctl scale nodegroup --cluster eksworkshop-eksctl --name $NODEGROUP_NAME --nodes 6 --nodes-max 6

#Install Kubeflow on Amazon EKS
curl --silent --location "https://github.com/kubeflow/kfctl/releases/download/v1.0.1/kfctl_v1.0.1-0-gf3edb9b_linux.tar.gz" | tar xz -C /tmp
sudo mv -v /tmp/kfctl /usr/local/bin


#Setup your configuration
cat << EoF > kf-install.sh
export AWS_CLUSTER_NAME=eksworkshop-eksctl
export KF_NAME=\${AWS_CLUSTER_NAME}

export BASE_DIR=${HOME}/environment
export KF_DIR=\${BASE_DIR}/\${KF_NAME}

# export CONFIG_URI="https://raw.githubusercontent.com/kubeflow/manifests/v1.0-branch/kfdef/kfctl_aws_cognito.v1.0.1.yaml"
export CONFIG_URI="https://raw.githubusercontent.com/kubeflow/manifests/v1.0-branch/kfdef/kfctl_aws.v1.0.1.yaml"

export CONFIG_FILE=\${KF_DIR}/kfctl_aws.yaml
EoF

source kf-install.sh

#Create Kubeflow setup directory
mkdir -p ${KF_DIR}
cd ${KF_DIR}

#Download configuration file
wget -O kfctl_aws.yaml $CONFIG_URI

# Modify the configuration file
sed -i '/region: us-east-2/ a \      enablePodIamPolicy: true' ${CONFIG_FILE}

sed -i -e 's/kubeflow-aws/'"$AWS_CLUSTER_NAME"'/' ${CONFIG_FILE}
sed -i "s@us-east-2@$AWS_REGION@" ${CONFIG_FILE}

sed -i "s@roles:@#roles:@" ${CONFIG_FILE}
sed -i "s@- eksctl-eksworkshop-eksctl-nodegroup-ng-a2-NodeInstanceRole-xxxxxxx@#- eksctl-eksworkshop-eksctl-nodegroup-ng-a2-NodeInstanceRole-xxxxxxx@" ${CONFIG_FILE}

#Until https://github.com/kubeflow/kubeflow/issues/3827 is fixed, install aws-iam-authenticator
curl -o aws-iam-authenticator https://amazon-eks.s3.us-west-2.amazonaws.com/1.15.10/2020-02-22/bin/linux/amd64/aws-iam-authenticator
chmod +x aws-iam-authenticator
sudo mv aws-iam-authenticator /usr/local/bin

#Deploy Kubeflow
#Apply configuration and deploy Kubeflow on your cluster:
cd ${KF_DIR}
kfctl apply -V -f ${CONFIG_FILE}

#Run below command to check the status
kubectl -n kubeflow get all


# open Kubeflow
kubectl port-forward svc/istio-ingressgateway -n istio-system 8080:80

# Creating s3 bucket for trained model
export HASH=$(< /dev/urandom tr -dc a-z0-9 | head -c6)
export S3_BUCKET=$HASH-eks-ml-data
aws s3 mb s3://$S3_BUCKET --region $AWS_REGION

#Setup AWS credentials in EKS cluster
#Create an IAM user ‘s3user’, attach S3 access policy and retrieve temporary credentials
aws iam create-user --user-name s3user
aws iam attach-user-policy --user-name s3user --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess
aws iam create-access-key --user-name s3user > /tmp/create_output.json

#Next, record the new user’s credentials into environment variables:
export AWS_ACCESS_KEY_ID_VALUE=$(jq -j .AccessKey.AccessKeyId /tmp/create_output.json | base64)
export AWS_SECRET_ACCESS_KEY_VALUE=$(jq -j .AccessKey.SecretAccessKey /tmp/create_output.json | base64)

#Apply to EKS cluster:
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: aws-secret
type: Opaque
data:
  AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID_VALUE
  AWS_SECRET_ACCESS_KEY: $AWS_SECRET_ACCESS_KEY_VALUE
EOF

#Run training using pod
#Create pod:
curl -LO https://raw.githubusercontent.com/matkalinowski/k8s_tutorial/master/mnist_train.yaml
envsubst < mnist_train.yaml | kubectl create -f -

#This will start a pod which will start the training and save the generated model in S3 bucket. Check status:
kubectl get pods








#https://managedkube.com/kubernetes/pod/failure/crashloopbackoff/k8sbot/troubleshooting/2019/02/12/pod-failure-crashloopbackoff.html
export NAMESPACE=eksworkshop
export PODNAME=myjupyter-0
kubectl -n ${NAMESPACE} describe pod ${PODNAME}

#pods for namespace
kubectl get pods -n ${NAMESPACE}

# logs
kubectl -n ${NAMESPACE} logs ${PODNAME} myjupyter