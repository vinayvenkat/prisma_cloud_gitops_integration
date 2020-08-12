// Copyright 2018 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//Copyright (c) 2009 The Go Authors. All rights reserved.
//
//Redistribution and use in source and binary forms, with or without
//modification, are permitted provided that the following conditions are
//met:
//
//   * Redistributions of source code must retain the above copyright
//notice, this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above
//copyright notice, this list of conditions and the following disclaimer
//in the documentation and/or other materials provided with the
//distribution.
//   * Neither the name of Google Inc. nor the names of its
//contributors may be used to endorse or promote products derived from
//this software without specific prior written permission.
//
//THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
//"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
//LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
//A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
//OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
//LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
//DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
//THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


// Copyright 2019 Palo Alto Networks Istio Security Adapter Author(s) 
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


// nolint:lll
// Generates the mygrpcadapter adapter's resource yaml. It contains the adapter's configuration, name, supported template
// names (metric in this case), and whether it is session or no-session based.
//go:generate $GOPATH/src/istio.io/istio/bin/mixer_codegen.sh -a mixer/adapter/pansecurityadapter/config/config.proto -x "-s=false -n pansecurityadapter -t authorization -t logentry"

package pansecurityadapter

import (
    "context"
    "fmt"
    "net"
    "net/http"
    "reflect"
    "google.golang.org/grpc"
    "bytes"
    "strings"
	rpc "github.com/gogo/googleapis/google/rpc"
    "istio.io/api/mixer/adapter/model/v1beta1"
    policy "istio.io/api/policy/v1beta1"
    "istio.io/istio/mixer/adapter/pansecurityadapter/config"
    "istio.io/istio/mixer/template/authorization"
    "istio.io/istio/mixer/template/logentry"
    "istio.io/istio/pkg/log"
    "istio.io/istio/mixer/pkg/status"
    "os"
	"io/ioutil"
	"encoding/json"
	"time"
    "cloud.google.com/go/logging"
    scontext "golang.org/x/net/context"
	"errors"
	"encoding/base64"
	"github.com/PaloAltoNetworks/pango"
)

type (
    // Server is basic server interface
    Server interface {
        Addr() string
        Close() error
        Run(shutdown chan error)
    }

    // MyGrpcAdapter supports metric template.
    MyGrpcAdapter struct {
        listener net.Listener
        server   *grpc.Server
    }

	// Security Policy definition
	SecurityPolicy struct {
        SourceService string `json:"source_service"`
        DestinationService string `json:"destination_service"`
        SourceNamespace string `json:"source_namespace"`
        DestinationNamespace string `json:"destination_namespace"`
        Protocol string `json:protocol`
		Action string `json:action`
	}

   CustomData struct {
	 pstring string
   }
)

var (
	_ logentry.HandleLogEntryServiceServer = &MyGrpcAdapter{}
    client *logging.Client
	logger *logging.Logger
	logInit bool
	log_prefix string

	_ authorization.HandleAuthorizationServiceServer = &MyGrpcAdapter{}
	confSecPolicy2 []SecurityPolicy
)


func handleConsoleLogging(sdata string, data interface{}) {

	if data != nil {
		log.Infof("%s: %s Data  %v", log_prefix, sdata, data)
	} else {
		log.Infof("%s: %s", log_prefix, sdata)
	}
}

func handleFileLogging(filename string) {
	log.Infof("==== handleFileLogging method invoked: %s \n", filename)
}

func handleCloudLogging(ProjectId string, data interface{}) {
	log.Infof("==== handleCloudLogging method invoked: %s \n", ProjectId)
	/* Check logger configuration and configure the logger */
	if logInit == false {
		if ProjectId == "" {
			handleConsoleLogging("GCP logging project not specified\n", nil)
		} else {
			handleConsoleLogging("Initialization sequence", nil)
            cinit := CustomData{pstring: "Initialization sequence"}
			initStackLogger(ProjectId)
			logToStackdriver(cinit)
		}
	} else {
		handleConsoleLogging("Stackdriver logging already configured\n", nil)
		if data != nil {
			logToStackdriver(data)
		}
	}
}

// HandleLogEntry records log entries
func (s *MyGrpcAdapter) HandleLogEntry(ctx context.Context, in *logentry.HandleLogEntryRequest) (*v1beta1.ReportResult, error) {

	var b bytes.Buffer
    cfg := &config.Params{}

    if in.AdapterConfig != nil {
        if err := cfg.Unmarshal(in.AdapterConfig.Value); err != nil {
            log.Errorf("error unmarshalling adapter config: %v", err)
            return nil, err
        }
    }

	if cfg.LogPrefix == "" {
		log_prefix = "panw_istio_logs"
	} else {
		log_prefix = cfg.LogPrefix
	}

	handleCloudLogging(cfg.ProjectId, nil)

    retString, rMap := instances(in.Instances)
	b.WriteString(fmt.Sprintf("HandleLogEntry invoked with:\n  Adapter config: %s\n  Instances: %s\n",
        cfg.String(), retString))
	fmt.Println("Instance record (strings):\n")
	fmt.Println(retString)
	// Convert to json 
	rjMap , _ := json.Marshal(rMap)
	handleConsoleLogging("Traffic Record JSON", string(rjMap))


	if cfg.FilePath == "" {
        fmt.Println(b.String())
    } else {
			var ret int
			if _, err := os.Stat(cfg.FilePath); os.IsNotExist(err) {
				fmt.Println("File does not exist. Create it...")
				ret = 1
			}

			if ret == 1 {
				_, err := os.OpenFile(cfg.FilePath, os.O_RDONLY|os.O_CREATE, 0666)
				if err != nil {
					log.Errorf("error creating file: %v", err)
				}

			}

			f, err:= os.OpenFile(cfg.FilePath, os.O_APPEND|os.O_WRONLY, 0666)
			if err != nil {
				log.Errorf("error opening file for append: %v", err)
				return nil, err
			}
		defer f.Close()

        log.Infof("Writing instances to file %s", f.Name())
        if _, err = f.Write(b.Bytes()); err != nil {
            log.Errorf("error writing to file: %v", err)
        }
	}
    return &v1beta1.ReportResult{}, nil
}

func initStackLogger(projectId string) {

	handleConsoleLogging("init stack driver logger", nil)
	ctx := scontext.Background()

    // Creates a client.
    var err error
    client, err = logging.NewClient(ctx, projectId)
    if err != nil {
        log.Fatalf("Failed to create client: %v", err)
    }

    // Sets the name of the log to write to.
    logName := "vv15-k8s-stack"

    // Selects the log to write to.
    logger = client.Logger(logName)

    logInit = true
	handleConsoleLogging("stack driver logger ready", nil)
}

func logToStackdriver(data interface{}) {
	logger.Log(logging.Entry{Payload: data})
}

func instances(in []*logentry.InstanceMsg) (string, map[string]interface{}) {
    var b bytes.Buffer
    smap := make(map[string]interface{})
    for _, inst := range in {
        timeStamp := inst.Timestamp.Value.String()
        severity := inst.Severity
        fmt.Println("TimeStamp: ", timeStamp)
        fmt.Println("Severity: ", severity)
        /* for k, v := range inst.Variables {
            fmt.Println(k, ": ", decodeValue(v.GetValue()))
        }
		*/
		b.WriteString(fmt.Sprintf("'%s':\n"+
            "{\n"+
            "\tTimestamp = %v\n"+
            "\tSeverity = %v\n",
             inst.Name, inst.Timestamp.Value.String(),
				   inst.Severity))

		smap["Timestamp"] = string(timeStamp)

		for k, v := range inst.Variables {
			b.WriteString(fmt.Sprintf("\t%s = %v\n", k, decodeValue(v.GetValue())))
            smap[k] = decodeValue(v.GetValue())
		}
		b.WriteString(fmt.Sprintf("\n}"))
		for key, value := range smap {
			fmt.Println(key, "=", value)
		}
    }
    return b.String(), smap
}

// HandleLogEntry records log entries
func (s *MyGrpcAdapter) HandleAuthorization(ctx context.Context, in *authorization.HandleAuthorizationRequest) (*v1beta1.CheckResult, error) {

	var b bytes.Buffer
	log.Infof("New Mixer CHECK REQUEST. HandleAuthorization invoked")
    cfg := &config.Params{}

    if in.AdapterConfig != nil {
        if err := cfg.Unmarshal(in.AdapterConfig.Value); err != nil {
            log.Errorf("error unmarshalling adapter config: %v", err)
            return nil, err
        }
    }

	b.WriteString(fmt.Sprintf("HandleAuthorization invoked with:\n  Adapter config: %s\n  Instances: %s\n",
        cfg.String(), in.Instance))
    log.Infof("Instance value: %v", in.Instance.Name)

	if in.Instance.Action.Properties != nil {
        for key, val := range in.Instance.Action.Properties {
            log.Infof("Property key %s : Value : %s : %s", key, val.Value, decodeValue(val.Value))
        }
    }

	sp :=populateSecurityPolicyParams(in)

	if cfg.FilePath == "" {
        fmt.Println(b.String())
    } else {
			var ret int
			if _, err := os.Stat(cfg.FilePath); os.IsNotExist(err) {
				fmt.Println("File does not exist. Create it...")
				ret = 1
			}

			if ret == 1 {
				_, err := os.OpenFile(cfg.FilePath, os.O_RDONLY|os.O_CREATE, 0666)
				if err != nil {
					log.Errorf("error creating file: %v", err)
				}

			}

			f, err:= os.OpenFile(cfg.FilePath, os.O_APPEND|os.O_WRONLY, 0666)
			if err != nil {
				log.Errorf("error opening file for append: %v", err)
				return nil, err
			}
		defer f.Close()

        log.Infof("writing instances to file %s", f.Name())
        if _, err = f.Write(b.Bytes()); err != nil {
            log.Errorf("error writing to file: %v", err)
        }
	}

    var found bool
	found,_ = checkAuthorization(confSecPolicy2, sp)

	cr := v1beta1.CheckResult{}
	if found {
			log.Infof("RESULT: ACCESS ALLOWED. Request parameters match configured security policies.")
		    cr.Status =	status.WithMessage(rpc.OK, "Match found")
		    cr.ValidDuration = 100
		    cr.ValidUseCount = 500
	} else {
			log.Infof("RESULT: ACCESS DENIED. Request parameters do not match configured security policies.")
		    cr.Status =	status.WithMessage(rpc.PERMISSION_DENIED, "Match not found")
		    cr.ValidDuration = 500
		    cr.ValidUseCount = 600
	}

    return &cr, nil
}

func checkAuthorization(confSecPolicy []SecurityPolicy, runtimeSecPolicy SecurityPolicy) (retValue bool, e error) {

	for idx, item := range confSecPolicy {
        log.Infof("Comparing configured security policy %d", idx)
		log.Infof("Configured security policy: %s", item)
		log.Infof("Runtime security policy: %s", runtimeSecPolicy)
		if item.SourceService == runtimeSecPolicy.SourceService &&
			item.SourceNamespace == runtimeSecPolicy.SourceNamespace &&
			item.DestinationNamespace == runtimeSecPolicy.DestinationNamespace &&
			item.DestinationService == runtimeSecPolicy.DestinationService &&
			item.Protocol == runtimeSecPolicy.Protocol {
			return true, nil
		}
	}
	log.Info("No security policy match found. Returning denied.")
	return false,nil
}

func decodeDimensions(in map[string]*policy.Value) map[string]interface{} {
    out := make(map[string]interface{}, len(in))
    for k, v := range in {
        out[k] = decodeValue(v.GetValue())
    }
    return out
}


func populateSecurityPolicyParams(in *authorization.HandleAuthorizationRequest) (sp SecurityPolicy){

	sec_policy := SecurityPolicy{}

    log.Infof("Subject -> User: %s", in.Instance.Subject.User)
	log.Infof("Subject -> Group: %s", in.Instance.Subject.Groups)


	for key, val := range in.Instance.Subject.Properties {
		if key == "source_namespace" {
			log.Infof("Source namespace: %s", decodeValue(val.Value))
			sec_policy.SourceNamespace = decodeValue(val.Value).(string)
		} else if key == "source_service" {
			log.Infof("Source service: %s", decodeValue(val.Value))
			sec_policy.SourceService = decodeValue(val.Value).(string)
		}
	}
	for key, val := range in.Instance.Action.Properties {
		if key == "protocol" {
			log.Infof("Action -> Properties -> protocol: %s", decodeValue(val.Value))
			sec_policy.Protocol = decodeValue(val.Value).(string)
		}
	}
    log.Infof("Action -> Namespace: %s", in.Instance.Action.Namespace)
	log.Infof("Action -> Service: %s", in.Instance.Action.Service)
	sec_policy.DestinationNamespace = in.Instance.Action.Namespace
	sec_policy.DestinationService = in.Instance.Action.Service
	return sec_policy
}


func decodeValue(in interface{}) interface{} {
    switch t := in.(type) {
    case *policy.Value_StringValue:
        return t.StringValue
    case *policy.Value_Int64Value:
        return t.Int64Value
    case *policy.Value_DoubleValue:
        return t.DoubleValue
    case *policy.Value_IpAddressValue:
        ipV := t.IpAddressValue.Value
        ipAddress := net.IP(ipV)
        str := ipAddress.String()
        return str
    case *policy.Value_DurationValue:
        return t.DurationValue.Value.String()
    default:
        return fmt.Sprintf("%v", in)
    }
}

func retry(attempts int, sleep time.Duration, fn func() error) error {
    if err := fn(); err != nil {
        if s, ok := err.(stop); ok {
            // Return the original error for later checking
            return s.error
        }

        if attempts--; attempts > 0 {
            time.Sleep(sleep * time.Second)
            return retry(attempts, 2*sleep, fn)
        }
        return err
    }
    return nil
}

type stop struct {
    error
}

func simulatorEndpoint(security_policy_endpoint string, username string, password string) error {
	endpoint_url := fmt.Sprintf("http://%s:9080", security_policy_endpoint)
	log.Infof("The Policy simulator endpoint is: %s", endpoint_url)
	req, err := http.NewRequest("GET", endpoint_url, nil)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Infof("Error occurred while trying to retrieve security policies from remote endpoint")
		return err
	}
	body, err:= ioutil.ReadAll(resp.Body)
	log.Infof("Response from the Security Policy API Server: %s", string(body))
	resp.Body.Close()
	_ = json.Unmarshal(body, &confSecPolicy2)
	log.Infof("Unmarshaled data information: %s %s", confSecPolicy2, reflect.TypeOf(confSecPolicy2))
	return nil
}

func trimString(s string) string {
    var t string
	var start, end int
	seen := false
	ss := "'"
	for idx, _ := range(s) {
		if s[idx] == ss[0] && seen == false {
			start = idx + 1
			seen = true
			continue
		}
		if s[idx] == ss[0] {
			end = idx - 1
			break
		}
	}
    t = s[start:end + 1]
	return t
}


func getPanoramaPolicies(security_policy_endpoint string, panorama_d_username string,
						panorama_d_password string) error {

	var err error
	var sdag string
	var ddag string

	confSecPolicy2 = nil

    c := &pango.Panorama{Client: pango.Client{
        Hostname: security_policy_endpoint,
        Username: panorama_d_username,
        Password: panorama_d_password,
        Logging: pango.LogAction | pango.LogOp,
    }}
    if err = c.Initialize(); err != nil {
        log.Infof("Failed to initialize client: %s", err)
        return err
    }
    log.Infof("Initialize ok")
	pols, errs := c.Policies.Security.GetList("vv15-gke-dg", "")
    if errs != nil {
        log.Infof("error occurred: %s", errs)
    }
    log.Infof("%s", pols)
    for _, pol := range(pols) {
		log.Infof(" Processing Security Policy: %s", pol)
        d, err := c.Policies.Security.Get("vv15-gke-dg", "pre-rulebase", pol)
		// Each security policy references an address object or DAG. 
		// for the source and the destionation 
		// Extract this information first. 
        if err == nil {
            log.Infof("policy: Source address: %s  %s", d.SourceAddresses, d.DestinationAddresses)
			log.Infof("Application services: %s", d.Services)
			sdag = d.SourceAddresses[0]
			ddag = d.DestinationAddresses[0]
        }
		log.Infof("Source Address group: %s Destination Address Group: %s", sdag, ddag)
        sm, err := c.Objects.AddressGroup.Get("vv15-gke-dg", sdag)
        if err != nil {
            log.Infof("err: %s", err)
		}

        log.Infof("Source Address Group: %s", sm.Name)
		log.Infof("Source Namespace: %s Services: %s", sm.Tags[0], sm.DynamicMatch)
		services := strings.Split(sm.DynamicMatch, "and")

        dm, err := c.Objects.AddressGroup.Get("vv15-gke-dg", ddag)
        if err != nil {
            log.Infof("err: %s", err)
        }
        log.Infof("Destination Address Group: %s", dm.Name)
		log.Infof("Destination Namespace: %s Services: %s", dm.Tags[0], dm.DynamicMatch)
		dservices := strings.Split(dm.DynamicMatch, "and")

		for _, ssvc := range(services) {
			for _, dsvc:= range(dservices) {
				ts := ssvc
				td := dsvc
				//log.Infof("Starting tuple is: before::: %s:%s", ts,td)
				ts = trimString(ts)
				td = trimString(td)
				//log.Infof("After::: %s:%s", ts, td)
				if ts == td {
					//log.Infof("omit same services")
					continue
				}
				lp := SecurityPolicy{}
				lp.SourceNamespace = sm.Tags[0]
				lp.DestinationNamespace = dm.Tags[0]
				lp.SourceService = ts
				lp.DestinationService = td
				if d.Services[0] == "service-http" {
					lp.Protocol = "http"
				}
				lp.Action = d.Action
				log.Infof("Adding new transformed security policy: %s", lp)
				confSecPolicy2 = append(confSecPolicy2, lp)
			}
		}
    }
	log.Infof("%s ", confSecPolicy2)
	return nil
}

// Retrieve security policies from Policy Server
func remoteFetchSecurityPolicy() error {
	// the idea is to retrieve 
	// the endpoint for the Policy server 
	// from environment variables 

	// Retrieve the API server URL from the 
	// the environment variable SECURITY_POLICY_API_ENDPOINT

	var (
		panorama_username = ""
		panorama_password = ""
		panorama_username_decoded = ""
		panorama_password_decoded = ""
		p_flag = false
		endpointType string
	)

	endpointType = os.Getenv("SECURITY_POLICY_ENDPOINT_TYPE")

	if endpointType == "panorama" {
		log.Infof("The policies will be retrieved from Panorama")
		panorama_username = os.Getenv("PANORAMA_USERNAME")
		panorama_password = os.Getenv("PANORAMA_PASSWORD")
		log.Infof("%s %s", panorama_username, panorama_password)
		if panorama_username == "" || panorama_password == "" {
			log.Info("Cannot use panorama since no credentials supplied")
		} else {
			u_decoded , _ :=  base64.StdEncoding.DecodeString(panorama_username)
			p_decoded, _ := base64.StdEncoding.DecodeString(panorama_password)
			log.Infof("%s %s", u_decoded, p_decoded)
			panorama_username_decoded = string(u_decoded)
			panorama_password_decoded = string(p_decoded)
			p_flag = true
		}
		if panorama_username != "" && panorama_password != "" {
			log.Infof("%s %s", panorama_username_decoded, panorama_password_decoded)
		}
	} else {
		log.Infof("The policies will be retrieved from the simulator endpoint")
	}

	security_policy_endpoint := os.Getenv("SECURITY_POLICY_API_ENDPOINT")
    log.Infof("Security Policy Endpoint is at: %s", security_policy_endpoint)
	if security_policy_endpoint == "" {
		log.Fatal("Unable to retrieve the security policy endpoint. Please check configuration")
		return errors.New("SECURITY_POLICY_API_ENDPOINT has not been specified. Please check configuration")
	}

    tick := time.NewTicker(time.Minute * 1)
    done := make(chan bool)
	if p_flag == false {
		go scheduler(tick, done, security_policy_endpoint, "filler", "filler", simulatorEndpoint)
	} else {
		go scheduler(tick, done, security_policy_endpoint, panorama_username_decoded, panorama_password_decoded, getPanoramaPolicies)
	}
	return nil
}

func scheduler(tick *time.Ticker, done chan bool,
               endpoint string, username string, password string,
			   policy_func func(string, string, string) error) {
    for {
        select {
        case t := <-tick.C:
			fmt.Println("running timer task: ", t)
            policy_func(endpoint, username, password)
        case <-done:
			log.Infof("Interrupt signal received. Stopping timer")
            return
        }
    }
}


// Addr returns the listening address of the server
func (s *MyGrpcAdapter) Addr() string {
    return s.listener.Addr().String()
}

// Run starts the server run
func (s *MyGrpcAdapter) Run(shutdown chan error) {
    shutdown <- s.server.Serve(s.listener)
}

// Close gracefully shuts down the server; used for testing
func (s *MyGrpcAdapter) Close() error {
    if s.server != nil {
        s.server.GracefulStop()
    }

    if s.listener != nil {
        _ = s.listener.Close()
    }

    return nil
}

// NewMyGrpcAdapter creates a new adapter that listens at provided port.
func NewMyGrpcAdapter(addr string) (Server, error) {
    if addr == "" {
        addr = "0"
    }
    listener, err := net.Listen("tcp", fmt.Sprintf(":%s", addr))
    if err != nil {
        return nil, fmt.Errorf("unable to listen on socket: %v", err)
    }
    s := &MyGrpcAdapter{
        listener: listener,
    }
    fmt.Printf("listening on \"%v\"\n", s.Addr())
    s.server = grpc.NewServer()
    authorization.RegisterHandleAuthorizationServiceServer(s.server, s)
    logentry.RegisterHandleLogEntryServiceServer(s.server, s)
	retry(20, 5, remoteFetchSecurityPolicy)
    return s, nil
}
