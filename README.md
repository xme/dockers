# imap2thehive

imap2thehive image with analyzers installed

image built around: https://github.com/xme/dockers/tree/master/imap2thehive

Image name: `pipedrive/imap2thehive`

# Description
This image is a K8 ready version of imap2thehive. The Python script included in the image diviates slightly from the original version of XME.


# Live deployment
1. [Deploy via Jenkins][1]
2. After deploying, fetch the new tag that was pushed to Docker Hub. This is listed in the console output of the Jenkins job.
3. Update the tag in the K8 manifests in [chef-repo][2] and in [the-hive-kube][3]

[1]: https://jenkins.pipedrive.tools/job/baseimage-imap2thehive-docker/
[2]: https://github.com/pipedrive/chef-repo
[3]: https://github.com/pipedrive/the-hive-kube