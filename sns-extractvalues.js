/* global input, output */

// Inputs:
//   SNS Dimensions (required)
//   TopicArn (required)
//
// Outputs:
//   EC2InstanceId
//   AWSRegion
//   EBSDevice
//   NVMEDevice

var dimensions = input['SNS Dimensions'];
for (var i=0, size=dimensions.length; i < size; i++) {
    var item = dimensions[i];
    switch (item.name) {
        case "InstanceId":
            output.EC2InstanceId = item.value;
            break;
        case "device":
            output.EBSDevice = item.value;
            break;
    }
}

// Get the region from the topic arn, which looks like this:
// "arn:aws:sns:us-east-1:621503700583:Handle-low-disc-space"
var arn = input.TopicArn;
var parts = arn.split(":");
output.AWSRegion = parts[3];

output.NVMEdevice = output.EBSDevice.startsWith("nvme");
