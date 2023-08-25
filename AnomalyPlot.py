import matplotlib.pyplot as plt

# Time data in seconds
seconds = [15,30,45,60,75,90,105,120,135,150,165,180,195,210,225,240,255,270,285,300]

# Packet count data per second
count_values26 = [89,94,101,108,1440,99,110,102,113,110,1400,115,109,122,113,108,1360,102,108,115] 
count_values15 = [89,94,101,108,750,99,110,102,113,110,710,115,109,122,113,108,670,102,108,115] 
count_values09 = [89,94,101,108,385,99,110,102,113,110,340,115,109,122,113,108,295,102,108,115] 
count_values00 = [89,94,101,108,106,99,110,102,113,110,120,115,109,122,113,108,99,102,108,115]

# Create graphs
plt.plot(seconds, count_values09, label='35% CPU')
plt.plot(seconds, count_values15, label='60% CPU')
plt.plot(seconds, count_values26, label='100% CPU')
plt.plot(seconds, count_values00, label='Benign Traffic')

# Set values on the x-axis
plt.xticks([60, 120, 180, 240, 300])
plt.yticks([150, 350, 700, 1400])


# Add label for x-axis and y-axis.
plt.xlabel('secondi')
plt.ylabel('numero di pacchetti catturati')

# Add legend
plt.legend()

# Show graph
plt.show()
