import pickle
import pandas as pd

val = input("Choose the dataset : ")
print("")
print("Checking ....")
print("------------------------------")

try:
    test =pd.read_csv(val)
    with open('model.h5', 'rb') as pickle_file:
        content = pickle.load(pickle_file)


    print("Result: \n")
    hasil = content.predict(test)
    if 1 in hasil:
        print("Port Scanning detected")
    else:
        print("No Port Scanning detected")
except:
    print("No Port Scanning detected")

print("------------------------------")
