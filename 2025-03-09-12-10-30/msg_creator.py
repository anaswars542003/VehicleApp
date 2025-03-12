import socket
from pyasn1.type import univ, namedtype, constraint
from pyasn1.codec.der import encoder
import traci
import traci.constants as tc
import random

# Define the BSM message (same as before)
class Uint8(univ.Integer):
    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(0, 255)

class Position(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('latitude', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(-900000000, 900000000))),
        namedtype.NamedType('longitude', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(-1800000000, 1800000000))),
        namedtype.NamedType('elevation', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(-1000, 10000)))
    )

class VehicleInformation(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('speed', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(0, 255))),
        namedtype.NamedType('heading', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(0, 360))),
        namedtype.NamedType('direction', univ.Boolean())
    )

class BasicSafetyMessage(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('protocolVersion', Uint8()),
        namedtype.NamedType('position', Position()),
        namedtype.NamedType('vehicleInfo', VehicleInformation())
    )

# Create and populate the BSM message
bsm = BasicSafetyMessage()

bsm.setComponentByName('protocolVersion', 3)
sumocfg = "osm.sumocfg"
    
    # Start SUMO as a subprocess and establish a connection
traci.start(["sumo", "-c", sumocfg, "--step-length", "0.1"])
    
    # Variables to track our selected vehicle
tracked_vehicle = None
step = 0

host = 'localhost'
port = 65432

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Connect to the server
client_socket.connect((host, port))
    
    # Run the simulation
print("Starting simulation...")
i = 0
if traci.simulation.getMinExpectedNumber() > 0 and i < 10:
    traci.simulationStep()
    step += 1
        
        # Get list of vehicles in the simulation
    vehicle_list = traci.vehicle.getIDList()
        
        # If no tracked vehicle yet and vehicles are present, select a random one
    if tracked_vehicle is None and vehicle_list:
        tracked_vehicle = random.choice(vehicle_list)
        print(f"Step {step}: Selected vehicle {tracked_vehicle} for tracking")
        
        # If we have a tracked vehicle, check if it's still in the simulation
    if tracked_vehicle is not None:
        if tracked_vehicle in vehicle_list:
                # Collect vehicle data
            vehicle_data = {}
            vehicle_data[tc.VAR_POSITION] = traci.vehicle.getPosition(tracked_vehicle)
            vehicle_data[tc.VAR_SPEED] = traci.vehicle.getSpeed(tracked_vehicle)
            vehicle_data[tc.VAR_ANGLE] = traci.vehicle.getAngle(tracked_vehicle)

            position = Position()
            position.setComponentByName('latitude', int(vehicle_data[tc.VAR_POSITION][0]  * 10 ** 4))
            position.setComponentByName('longitude', int(vehicle_data[tc.VAR_POSITION][1]  * 10 ** 4)) 

            position.setComponentByName('elevation', 0)

            vehicle_info = VehicleInformation()
            vehicle_info.setComponentByName('speed', int(vehicle_data[tc.VAR_SPEED]))
            vehicle_info.setComponentByName('heading', int(vehicle_data[tc.VAR_ANGLE]))
            vehicle_info.setComponentByName('direction', True)
            bsm.setComponentByName('position', position)
            bsm.setComponentByName('vehicleInfo', vehicle_info)

            encoded_bsm = encoder.encode(bsm)

            

            try:
                # Send the binary data over TCP
                client_socket.sendall(encoded_bsm)
                print(f"Sent data: {encoded_bsm}")
            finally:
                
                i += 1
traci.close()
client_socket.close()




