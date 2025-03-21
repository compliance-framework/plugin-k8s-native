package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/configuration-service/sdk"
	"github.com/compliance-framework/plugin-k8s-native/internal"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/protobuf/types/known/timestamppb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type CompliancePlugin struct {
	logger hclog.Logger
	config map[string]string
}

func (l *CompliancePlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {

	l.config = req.GetConfig()
	return &proto.ConfigureResponse{}, nil
}

func (l *CompliancePlugin) Eval(request *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {

	ctx := context.TODO()

	observations, findings, err := l.EvaluatePolicies(ctx, request)
	if err != nil {
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}
	if err = apiHelper.CreateObservationsAndFindings(ctx, observations, findings); err != nil {
		l.logger.Error("Failed to send compliance validation results", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}
	return &proto.EvalResponse{
		Status: proto.ExecutionStatus_SUCCESS,
	}, err
}

func (l *CompliancePlugin) EvaluatePolicies(ctx context.Context, request *proto.EvalRequest) ([]*proto.Observation, []*proto.Finding, error) {
	startTime := time.Now()
	agentPodName := os.Getenv("POD_NAME")
	var errAcc error

	activities := make([]*proto.Activity, 0)
	findings := make([]*proto.Finding, 0)
	observations := make([]*proto.Observation, 0)

	config, err := rest.InClusterConfig()
	if err != nil {
		l.logger.Error("unable to set k8s config", "error", err)
		errAcc = errors.Join(errAcc, err)
		return observations, findings, errAcc
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		l.logger.Error("unable to define a clientset", "error", err)
		errAcc = errors.Join(errAcc, err)
		return observations, findings, errAcc
	}

	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		l.logger.Error("unable to list pods", "error", err)
		errAcc = errors.Join(errAcc, err)
		return observations, findings, errAcc
	}

	clusterData := make(map[string]interface{})
	var podsMetaData []interface{}
	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			podsMetaData = append(podsMetaData, map[string]interface{}{
				"Name":  pod.Name,
				"Image": container.Image,
			})
		}
	}

	_, err = clientset.RbacV1().ClusterRoles().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		l.logger.Info("RBAC not enabled", err)
		clusterData["RBACEnabled"] = false
	} else {
		l.logger.Info("RBAC enabled", err)
		clusterData["RBACEnabled"] = true
	}

	// ACTIVITY: pod configuration call
	podConfigSteps := make([]*proto.Step, 0)
	podConfigSteps = append(podConfigSteps, &proto.Step{
		Title:       "Fetch pod configuration from all namespaces",
		Description: "Fetch pod configuration from all namespaces, using internal k8s API.",
	})
	activities = append(activities, &proto.Activity{
		Title:       "Collect pod configurations",
		Description: "Collect pod configuration from all namespaces, and prepare collected data for validation in policy engine",
		Steps:       podConfigSteps,
	})

	clusterData["Pods"] = podsMetaData

	l.logger.Debug("evaluating clusterData data", clusterData)
	for _, policyPath := range request.GetPolicyPaths() {

		// ACTIVITY: policy bundle info
		policyBundleSteps := make([]*proto.Step, 0)
		policyBundleSteps = append(policyBundleSteps, &proto.Step{
			Title:       "Compile policy bundle",
			Description: "Using a locally addressable policy path, compile the policy files to an in memory executable.",
		})
		policyBundleSteps = append(policyBundleSteps, &proto.Step{
			Title:       "Execute policy bundle",
			Description: "Using previously collected JSON-formatted POD configurations, execute the compiled policies",
		})
		results, err := policyManager.New(ctx, l.logger, policyPath).Execute(ctx, "compliance_plugin", clusterData)
		if err != nil {
			l.logger.Error("policy evaluation failed", "error", err)
			errAcc = errors.Join(errAcc, err)
			return observations, findings, errAcc
		}
		activities = append(activities, &proto.Activity{
			Title:       "Execute policy",
			Description: "Prepare and compile policy bundles, and execute them using the prepared POD configuration data",
			Steps:       policyBundleSteps,
		})
		l.logger.Debug("local k8s evaluation completed", "results", results)

		subjectAttributeMap := map[string]string{
			"type": "k8s-native-env",
		}

		subjects := []*proto.SubjectReference{
			{
				Type:       "deployment-instance",
				Attributes: subjectAttributeMap,
				Title:      internal.StringAddressed("Deployment Instance"),
				Remarks:    internal.StringAddressed("A k8s deployment running checks against cluster/pod configuration"),
				Props: []*proto.Property{
					{
						Name:    "deployment-instance",
						Value:   agentPodName,
						Remarks: internal.StringAddressed("The local hostname of the machine where the plugin has been executed"),
					},
				},
			},
		}
		actors := []*proto.OriginActor{
			{
				Title: "The Continuous Compliance Framework",
				Type:  "assessment-platform",
				Links: []*proto.Link{
					{
						Href: "https://compliance-framework.github.io/docs/",
						Rel:  internal.StringAddressed("reference"),
						Text: internal.StringAddressed("The Continuous Compliance Framework"),
					},
				},
				Props: nil,
			},
			{
				Title: "Continuous Compliance Framework - K8S native Plugin",
				Type:  "tool",
				Links: []*proto.Link{
					{
						Href: "https://github.com/compliance-framework/plugin-k8s-native",
						Rel:  internal.StringAddressed("reference"),
						Text: internal.StringAddressed("The Continuous Compliance Framework' K8S Native Plugin"),
					},
				},
				Props: nil,
			},
		}
		components := []*proto.ComponentReference{
			{
				Identifier: "common-components/k8s-native",
			},
		}
		activities = append(activities, &proto.Activity{
			Title:       "Compile Results",
			Description: "Using the output from policy execution, compile the resulting output to Observations and Findings, marking any violations, risks, and other OSCAL-familiar data",
			Steps:       policyBundleSteps,
		})

		for _, result := range results {
			observationUUIDMap := internal.MergeMaps(subjectAttributeMap, map[string]string{
				"type":        "observation",
				"policy":      result.Policy.Package.PurePackage(),
				"policy_file": result.Policy.File,
				"policy_path": policyPath,
			})
			observationUUID, err := sdk.SeededUUID(observationUUIDMap)
			if err != nil {
				errAcc = errors.Join(errAcc, err)
				// We've been unable to do much here, but let's try the next one regardless.
				continue
			}

			findingUUIDMap := internal.MergeMaps(subjectAttributeMap, map[string]string{
				"type":        "finding",
				"policy":      result.Policy.Package.PurePackage(),
				"policy_file": result.Policy.File,
				"policy_path": policyPath,
			})
			findingUUID, err := sdk.SeededUUID(findingUUIDMap)
			if err != nil {
				errAcc = errors.Join(errAcc, err)
				// We've been unable to do much here, but let's try the next one regardless.
				continue
			}

			observation := proto.Observation{
				ID:         uuid.New().String(),
				UUID:       observationUUID.String(),
				Collected:  timestamppb.New(startTime),
				Expires:    timestamppb.New(startTime.Add(24 * time.Hour)),
				Origins:    []*proto.Origin{{Actors: actors}},
				Subjects:   subjects,
				Activities: activities,
				Components: components,
				RelevantEvidence: []*proto.RelevantEvidence{
					{
						Description: fmt.Sprintf("Policy %v was executed against the K8S configuration, using the K8S Native Compliance Plugin", result.Policy.Package.PurePackage()),
					},
				},
			}

			newFinding := func() *proto.Finding {
				return &proto.Finding{
					ID:        uuid.New().String(),
					UUID:      findingUUID.String(),
					Collected: timestamppb.New(time.Now()),
					Labels: map[string]string{
						"type":         "k8s-native",
						"host":         agentPodName,
						"_policy":      result.Policy.Package.PurePackage(),
						"_policy_path": result.Policy.File,
					},
					Origins:             []*proto.Origin{{Actors: actors}},
					Subjects:            subjects,
					Components:          components,
					RelatedObservations: []*proto.RelatedObservation{{ObservationUUID: observation.ID}},
					Controls:            nil,
				}
			}

			if len(result.Violations) == 0 {
				observation.Title = internal.StringAddressed(fmt.Sprintf("Local SSH Validation on %s passed.", result.Policy.Package.PurePackage()))
				observation.Description = fmt.Sprintf("Observed no violations on the %s policy within the Local SSH Compliance Plugin.", result.Policy.Package.PurePackage())
				observations = append(observations, &observation)

				finding := newFinding()
				finding.Title = fmt.Sprintf("No violations found on %s", result.Policy.Package.PurePackage())
				finding.Description = fmt.Sprintf("No violations found on the %s policy within the Local SSH Compliance Plugin.", result.Policy.Package.PurePackage())
				finding.Status = &proto.FindingStatus{
					State: runner.FindingTargetStatusSatisfied,
				}
				findings = append(findings, finding)
				continue
			}

			if len(result.Violations) > 0 {
				observation.Title = internal.StringAddressed(fmt.Sprintf("Validation on %s failed.", result.Policy.Package.PurePackage()))
				observation.Description = fmt.Sprintf("Observed %d violation(s) on the %s policy within the Local SSH Compliance Plugin.", len(result.Violations), result.Policy.Package.PurePackage())
				observations = append(observations, &observation)

				for _, violation := range result.Violations {
					finding := newFinding()
					finding.Title = violation.Title
					finding.Description = violation.Description
					finding.Remarks = internal.StringAddressed(violation.Remarks)
					finding.Status = &proto.FindingStatus{
						State: runner.FindingTargetStatusNotSatisfied,
					}
					findings = append(findings, finding)
				}
			}

		}

	}

	return observations, findings, errAcc

}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	compliancePluginObj := &CompliancePlugin{
		logger: logger,
	}
	// pluginMap is the map of plugins we can dispense.
	logger.Debug("initiating k8s native plugin")

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerGRPCPlugin{
				Impl: compliancePluginObj,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
