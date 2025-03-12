#!/usr/bin/env python

import os
import sys
import random
import traci
import traci.constants as tc
from datetime import datetime

# Check if SUMO_HOME is defined
if 'SUMO_HOME' in os.environ:
    tools = os.path.join(os.environ['SUMO_HOME'], 'tools')
    sys.path.append(tools)
else:
    sys.exit("Please declare environment variable 'SUMO_HOME'")

# Define a function to generate BSM from vehicle data
def generate_bsm(vehicle_id, vehicle_data):
    """
    Generate a Basic Safety Message (BSM) from vehicle data
    """
    timestamp = datetime.now().isoformat()
    
    # Basic Safety Message structure
    bsm = {
        "msg_id": "BSM",
        "timestamp": timestamp,
        "vehicle_id": vehicle_id,
        "position": {
            "latitude": vehicle_data[tc.VAR_POSITION][0],  # x position as pseudo-latitude
            "longitude": vehicle_data[tc.VAR_POSITION][1],  # y position as pseudo-longitude
            "elevation": 0.0  # SUMO typically uses 2D, so elevation is 0
        },
        "motion": {
            "speed": vehicle_data[tc.VAR_SPEED],  # in m/s
            "heading": vehicle_data[tc.VAR_ANGLE],  # in degrees
            "acceleration": vehicle_data.get(tc.VAR_ACCELERATION, 0.0)  # in m/s²
        },
        "vehicle_size": {
            "length": vehicle_data[tc.VAR_LENGTH],  # in m
            "width": vehicle_data[tc.VAR_WIDTH]  # in m
        },
        "lane_id": vehicle_data[tc.VAR_LANE_ID],
        "road_id": vehicle_data[tc.VAR_ROAD_ID]
    }
    
    return bsm

def run_simulation():
    # Start SUMO with your network file
    # Note: Replace 'your_network.sumocfg' with your actual SUMO configuration file
    sumocfg = "osm.sumocfg"
    
    # Start SUMO as a subprocess and establish a connection
    traci.start(["sumo", "-c", sumocfg, "--step-length", "0.1"])
    
    # Variables to track our selected vehicle
    tracked_vehicle = None
    step = 0
    
    # Run the simulation
    print("Starting simulation...")
    while traci.simulation.getMinExpectedNumber() > 0:
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
                vehicle_data[tc.VAR_LENGTH] = traci.vehicle.getLength(tracked_vehicle)
                vehicle_data[tc.VAR_WIDTH] = traci.vehicle.getWidth(tracked_vehicle)
                vehicle_data[tc.VAR_LANE_ID] = traci.vehicle.getLaneID(tracked_vehicle)
                vehicle_data[tc.VAR_ROAD_ID] = traci.vehicle.getRoadID(tracked_vehicle)
                
                try:
                    vehicle_data[tc.VAR_ACCELERATION] = traci.vehicle.getAcceleration(tracked_vehicle)
                except:
                    vehicle_data[tc.VAR_ACCELERATION] = 0.0
                
                # Generate BSM
                bsm = generate_bsm(tracked_vehicle, vehicle_data)
                
                # Print BSM (in a real application, you might want to save this to a file or database)
                print(f"Step {step}: BSM for vehicle {tracked_vehicle}:")
                for key, value in bsm.items():
                    print(f"  {key}: {value}")
                print("---")
            else:
                print(f"Step {step}: Tracked vehicle {tracked_vehicle} is out of scope now")
                # Vehicle is no longer in the simulation
                tracked_vehicle = None
                print("Simulation will end as the tracked vehicle is out of scope")
                break
    
    # Close the TraCI connection
    traci.close()
    print("Simulation complete")

if __name__ == "__main__":
    run_simulation()
