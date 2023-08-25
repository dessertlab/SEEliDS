import matplotlib.pyplot as plt

# Time data in seconds
secondi = [15,30,45,60,75,90,105,120,135,150,165,180,195,210,225,240,255,270,285,300]

# Energy consumption data per second 
count_values26 = [184,198,217,231,1452,258,270,285,283,260,1510,275,285,282,303,300,1550,298,299,305] 
count_values15 = [184,198,217,231,766,258,270,285,283,260,824,275,285,282,303,300,865,298,299,305] 
count_values09 = [184,198,217,231,456,258,270,285,283,260,515,275,285,282,303,300,558,298,299,305] 
count_values00 = [184,198,217,231,246,258,270,285,283,260,270,275,285,282,303,300,294,298,299,305]

# Create graphs
plt.plot(secondi, count_values09, label='35% CPU')
plt.plot(secondi, count_values15, label='60% CPU')
plt.plot(secondi, count_values26, label='100% CPU')
plt.plot(secondi, count_values00, label='traffico benigno')

# Set values on the x-axis
plt.xticks([60, 120, 180, 240, 300])
plt.yticks([250, 500, 800, 1500])

# Add label for x-axis and y-axis.
plt.xlabel('secondi')
plt.ylabel('consumo energetico in mW')

# Add legend
plt.legend()

# Show graph
plt.show()
