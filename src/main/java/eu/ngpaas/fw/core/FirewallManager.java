package eu.ngpaas.fw.core;

import static org.slf4j.LoggerFactory.getLogger;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.ngpaas.pmlib.ForwardingObjectiveList;
import eu.ngpaas.pmlib.PolicyAction;
import eu.ngpaas.pmlib.PolicyCondition;
import eu.ngpaas.pmlib.PolicyHelper;
import eu.ngpaas.pmlib.PolicyRule;
import eu.ngpaas.pmlib.PolicyRules;
import eu.ngpaas.pmlib.PolicyService;
import eu.ngpaas.pmlib.PolicyVariableType;
import eu.ngpaas.pmlib.SimpleResponse;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Service;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;
import org.onlab.osgi.DefaultServiceDirectory;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TpPort;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.slf4j.Logger;


@Component(immediate = true)
@Service
public class FirewallManager implements PolicyService {
    private static final int FLOW_PRIORITY = 100;
    private final Logger log = getLogger(getClass());
    private DeviceId device = null;
    //Instantiate the required services
    private FlowObjectiveService flowObjectiveService = DefaultServiceDirectory.getService(FlowObjectiveService.class);
    private CoreService coreService = DefaultServiceDirectory.getService(CoreService.class);
    private DeviceService deviceService = DefaultServiceDirectory.getService(DeviceService.class);
    private HostService hostService = DefaultServiceDirectory.getService(HostService.class);
    private FlowRuleService flowRuleService = DefaultServiceDirectory.getService(FlowRuleService.class);
    private WebTarget RESTtarget = ClientBuilder.newClient(new ClientConfig())
                                                .register(HttpAuthenticationFeature.basic("onos", "rocks"))
                                                .target(UriBuilder.fromUri("http://localhost:8181/onos/policymanager")
                                                                  .build());

    @Activate
    protected void activate() {
        log.info("Firewall Policy started");
        //The endpoint MUST match the policy type
        Response response = RESTtarget.path("policytype/register/firewall")
                                      .request(MediaType.APPLICATION_JSON)
                                      .put(Entity.text(""));
        if (response.getStatus() != Response.Status.OK.getStatusCode()) {
            log.info("Policy Framework not found.");
            throw new RuntimeException();
        }
        log.info("Firewall policy type successfully registered.");

    }

    @Deactivate
    protected void deactivate() {
        log.info("Firewall Policy stopping");
        log.info("De-registering Firewall Policy from PM");
        Response response = RESTtarget.path("policytype/deregister/firewall").request(MediaType.APPLICATION_JSON)
                                      .delete();
        String prsJSON = response.readEntity(String.class);
        log.info(prsJSON);
        PolicyRules prs = parsePolicyRules(prsJSON);
        for (PolicyRule pr : prs.getPolicyRules()) {
            remove(pr);
        }
        log.info("Firewall Policies Deleted");
    }


    public PolicyRules parsePolicyRules(String json) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        PolicyRules policyRules = null;
        try {
            policyRules = mapper.readValue(json, PolicyRules.class);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return policyRules;
    }

    @Override
    public SimpleResponse formalValidation(PolicyRule pr) {
        CopyOnWriteArrayList<String> validconds = new CopyOnWriteArrayList<>(
            new String[] {"src_ip", "dst_ip", "src_mac", "dst_mac", "src_port", "dst_port", "tr_prot"});
        CopyOnWriteArrayList<String> validactions = new CopyOnWriteArrayList<>(new String[] {"allow"});
        SimpleResponse sr;
        sr = PolicyHelper.validateVariables(pr, validconds, validactions);
        if (!sr.isSuccess()) {
            return sr;
        }
        log.info("All variables valid");
        sr = PolicyHelper.validateConditionValue(pr, "src_ip", PolicyVariableType.IPV4);
        if (!sr.isSuccess()) {
            log.info(sr.toJSON());
            return sr;
        }
        log.info("src_ip valid");
        sr = PolicyHelper.validateConditionValue(pr, "dst_ip", PolicyVariableType.IPV4);
        if (!sr.isSuccess()) {
            return sr;
        }

        sr = PolicyHelper.validateConditionValue(pr, "src_mac", PolicyVariableType.MAC);
        if (!sr.isSuccess()) {
            return sr;
        }

        sr = PolicyHelper.validateConditionValue(pr, "dst_mac", PolicyVariableType.MAC);
        if (!sr.isSuccess()) {
            return sr;
        }

        sr = PolicyHelper.validateConditionValue(pr, "src_port", PolicyVariableType.PORT);
        if (!sr.isSuccess()) {
            return sr;
        }

        sr = PolicyHelper.validateConditionValue(pr, "dst_port", PolicyVariableType.PORT);
        if (!sr.isSuccess()) {
            return sr;
        }

        CopyOnWriteArrayList<String> validprot = new CopyOnWriteArrayList<>(new String[] {"tcp", "udp"});
        sr = PolicyHelper.validateConditionValue(pr, "tr_prot", validprot);
        if (!sr.isSuccess()) {
            return sr;
        }

        CopyOnWriteArrayList<String> validallow = new CopyOnWriteArrayList<>(new String[] {"false"});
        sr = PolicyHelper.validateActionValue(pr, "allow", validallow);
        if (!sr.isSuccess()) {
            return sr;
        }

        HashMap<String, CopyOnWriteArrayList<CopyOnWriteArrayList<String>>> mustCoexistDict = new HashMap<>();
        //mustCoexistDict.put


        //SimpleResponse restResponse;
        //log.info("FW policy: " + pr.toJSONString());
        //List<String> supported_conds = Arrays.asList("src_ip", "dst_ip","src_mac","dst_mac","src_port","dst_port",
        // "tr_prot");
        //List<String> supported_actions = Arrays.asList("allow");
        //for (CopyOnWriteArrayList<PolicyCondition> clause: pr.getPolicyConditions()){
        //    for (PolicyCondition pc: clause){
        //        if (!supported_conds.contains(pc.getPolicyVariable())){
        //            restResponse = new SimpleResponse("Formal error: Parameter " + pc.getPolicyVariable() + "
        // invalid.", false);
        //            return restResponse;
        //        }
        //    }
        //}
//
        //if (pr.getPolicyActions().size()>1) return new SimpleResponse("Formal error: Only one action is supported",
        // false);
        ////if (!supported_actions.contains(pr.getPolicyActions().get(0).getPolicyVariable()) || !pr.getPolicyActions
        // ().get(0).getPolicyValue().equalsIgnoreCase("false"))
        //if (!supported_actions.contains(pr.getPolicyActions().get(0).getPolicyVariable()) )
        //    return new SimpleResponse("Formal error: Incorrect action. Policy action variable must be 'allow'",
        // false);
//
        //if (!pr.getPolicyActions().get(0).getPolicyValue().equalsIgnoreCase("false"))
        //    return new SimpleResponse("Formal error: Firewall policies only support dropping traffic, not allowing
        // it. Thus, the action value must be 'false'.", false);
//
        return new SimpleResponse("Formal validated.", true);
    }

    @Override
    public SimpleResponse contextValidation(PolicyRule pr) {
        return new SimpleResponse("Policy context validated", true);
    }

    @Override
    public void enforce(PolicyRule pr) {
        PolicyAction pa = pr.getPolicyActions().get(0);
        ApplicationId applicationId = coreService.registerApplication("Firewall" + String.valueOf(pr.getId()));
        ForwardingObjective fwdObj;
        for (CopyOnWriteArrayList<PolicyCondition> clause : pr.getPolicyConditions()) {
            device = null;
            fwdObj = getFwdObj(clause, pa, pr.getPriority(), applicationId).add();
            // If a device (attachment point) has been identified remove the FW rule from there.
            // Else remove from everywhere in the network.
            if (device != null) {
                flowObjectiveService.forward(device, fwdObj);
            } else {
                for (Device d : deviceService.getDevices()) {
                    flowObjectiveService.forward(d.id(), fwdObj);
                }
            }
        }
    }

    @Override
    public ForwardingObjectiveList getFlowRules(PolicyRule pr) {
        ForwardingObjectiveList forwardingObjectiveList = new ForwardingObjectiveList();
        PolicyAction pa = pr.getPolicyActions().get(0);
        ApplicationId applicationId = coreService.registerApplication("Firewall" + String.valueOf(pr.getId()));
        ForwardingObjective fwdObj;
        for (CopyOnWriteArrayList<PolicyCondition> clause : pr.getPolicyConditions()) {
            device = null;
            fwdObj = getFwdObj(clause, pa, pr.getPriority(), applicationId).add();
            forwardingObjectiveList.getList().add(fwdObj);
            // If a device (attachment point) has been identified remove the FW rule from there.
            // Else remove from everywhere in the network.
            List<DeviceId> devices = new ArrayList();
            if (device != null) {
                devices.add(device);
            } else {
                for (Device d : deviceService.getDevices()) {
                    devices.add(d.id());
                }
            }
            forwardingObjectiveList.getDevices().add(devices);
        }
        return forwardingObjectiveList;
    }


    // Get firewall rule
    private ForwardingObjective.Builder getFwdObj(CopyOnWriteArrayList<PolicyCondition> pcs, PolicyAction pa,
                                                  int priority, ApplicationId applicationId) {

        // Create the required variables
        String protocol = "none";
        int src_port = 0;
        int dst_port = 0;

        // Create the traffic selector that will define the FW rule.
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();

        // For now consider only IPV4 traffic.
        selector.matchEthType(Ethernet.TYPE_IPV4);

        // Go through the conditions and start building the trafficSelector object.
        for (PolicyCondition pc : pcs) {

            // If a device is provided, the FW rule should be added there.
            if (pc.getPolicyVariable().equalsIgnoreCase("device")) {
                if (deviceService.getDevice(DeviceId.deviceId(pc.getPolicyValue())) != null) {
                    if (device == null) {
                        device = DeviceId.deviceId(pc.getPolicyValue());
                    }
                }
            }

            // Try to identify (if not already done) the attachment point, from the src_mac field. Also update the
            // traffic selector.
            else if (pc.getPolicyVariable().equalsIgnoreCase("src_mac")) {
                if (!hostService.getHostsByMac(MacAddress.valueOf(pc.getPolicyValue())).isEmpty()) {
                    if (device == null) {
                        device = hostService.getHostsByMac(MacAddress.valueOf(pc.getPolicyValue())).iterator().next()
                                            .location().deviceId();
                    }
                }
                selector.matchEthSrc((MacAddress.valueOf(pc.getPolicyValue())));
            }

            // Try to identify (if not already done) the attachment point, from the src_ip field. Also update the
            // traffic selector.
            else if (pc.getPolicyVariable().equalsIgnoreCase("src_ip")) {
                if (!hostService.getHostsByIp(IpAddress.valueOf(pc.getPolicyValue())).isEmpty()) {
                    if (device == null) {
                        device = hostService.getHostsByIp(IpAddress.valueOf(pc.getPolicyValue())).iterator().next()
                                            .location().deviceId();
                    }
                }
                selector.matchIPSrc(IpPrefix.valueOf(IpAddress.valueOf(pc.getPolicyValue()), 32));
            }

            // Try to identify (if not already done) the attachment point, from the dst_mac field. Also update the
            // traffic selector.
            else if (pc.getPolicyVariable().equalsIgnoreCase("dst_mac")) {
                if (!hostService.getHostsByMac(MacAddress.valueOf(pc.getPolicyValue())).isEmpty()) {
                    if (device == null) {
                        device = hostService.getHostsByMac(MacAddress.valueOf(pc.getPolicyValue())).iterator().next()
                                            .location().deviceId();
                    }
                }
                selector.matchEthDst((MacAddress.valueOf(pc.getPolicyValue())));
            }

            // Try to identify (if not already done) the attachment point, from the dst_ip field. Also update the
            // traffic selector.
            else if (pc.getPolicyVariable().equalsIgnoreCase("dst_ip")) {
                if (!hostService.getHostsByIp(IpAddress.valueOf(pc.getPolicyValue())).isEmpty()) {
                    if (device == null) {
                        device = hostService.getHostsByIp(IpAddress.valueOf(pc.getPolicyValue())).iterator().next()
                                            .location().deviceId();
                    }
                }
                selector.matchIPDst(IpPrefix.valueOf(IpAddress.valueOf(pc.getPolicyValue()), 32));
            }

            // Update the traffic selector with transport protocol and transport port information
            else if (pc.getPolicyVariable().equalsIgnoreCase("tr_prot")) {
                protocol = pc.getPolicyValue();
            } else if (pc.getPolicyVariable().equalsIgnoreCase("src_port")) {
                src_port = Integer.valueOf(pc.getPolicyValue());
            } else if (pc.getPolicyVariable().equalsIgnoreCase("dst_port")) {
                dst_port = Integer.valueOf(pc.getPolicyValue());
            }
        }

        if (protocol.equalsIgnoreCase("tcp")) {
            selector.matchIPProtocol(IPv4.PROTOCOL_TCP);
            if (src_port != 0) {
                selector.matchTcpSrc(TpPort.tpPort(src_port));
            }
            if (dst_port != 0) {
                selector.matchTcpDst(TpPort.tpPort(dst_port));
            }
        } else if (protocol.equalsIgnoreCase("udp")) {
            selector.matchIPProtocol(IPv4.PROTOCOL_UDP);
            if (src_port != 0) {
                selector.matchUdpSrc(TpPort.tpPort(src_port));
            }
            if (dst_port != 0) {
                selector.matchUdpDst(TpPort.tpPort(dst_port));
            }
        }

        // Create the traffic treatment object.
        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
        treatment.drop();

        // Create and push the forwarding objective.
        return DefaultForwardingObjective.builder()
                                         .makePermanent()
                                         .withPriority(FLOW_PRIORITY + priority)
                                         .withSelector(selector.build())
                                         .withTreatment(treatment.build())
                                         .fromApp(applicationId)
                                         .withFlag(ForwardingObjective.Flag.VERSATILE);
    }

    @Override
    public void remove(PolicyRule pr) {
        flowRuleService.removeFlowRulesById(coreService.getAppId("Firewall" + String.valueOf(pr.getId())));
        /*PolicyAction pa = pr.getPolicyActions().get(0);
        ForwardingObjective fwdObj;
        for (CopyOnWriteArrayList<PolicyCondition> clause : pr.getPolicyConditions()){
            fwdObj = getFwdObj(clause, pa, pr.getPriority()).remove();
            // If a device (attachment point) has been identified remove the FW rule from there.
            // Else remove from everywhere in the network.
            if (device != null) flowObjectiveService.forward(device,fwdObj);
            else{
                for (Device d:deviceService.getDevices()){
                    flowObjectiveService.forward(d.id(),fwdObj);
                }
            }
        }*/
    }
}
