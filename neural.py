import sympy as s
import matplotlib.pyplot as plt

#define relu
xs,w1s,w2s,ts=s.symbols("x w1 w2 t")
alpha = 0.01
h = s.Piecewise((w1s*xs, w1s*xs > 0), (alpha*w1s*xs, True))
y=w2s*h
l=(ts-y)**2

#derivatives
d1=s.diff(l,w1s)
d2=s.diff(l,w2s)

#define basic nn(x=input,w1=weigt1,w2=weight2,lr=learning rate,t=target)

def nn(x,w1,w2,lr,t,epoch=200,alpha=0.01,p=20):
    a=[]

    pr=float("inf")

    pc=0  #patiance counter

    for i in range(epoch):
        #forward pass
        z=w1*x

        h=z if z>0 else alpha*z    #hidden layer

        y=w2*h     #output layer

        l=(t-y)**2   #loss
        #backpropogation
        a1=float(d1.subs({xs:x,w1s:w1,w2s:w2,ts:t}))
        a2=float(d2.subs({xs:x,w1s:w1,w2s:w2,ts:t}))
        a.append([i,w1,w2,lr,h,y,l])
        w1=w1-(lr*a1)
        w2=w2-(lr*a2)
        #stop coditon
        if l < 1e-6:
            break
        #dynamic learning rate adjusment
        if l  < pr-1e-9:
            lr *= 1.02
            pc=0  # reward good step
        else:
            lr *= 0.5 
            pc+=1    # punish overshoot

        # clip learning rate to safe range
        lr= max(min(lr, 1.0), 1e-6)

        pr=l
        if pc>=p:
            print(f"Early stopping at epoch{i} (patiance reached)")
            break

    return a

x=float(input("x"))
w1=float(input("w1"))
w2=float(input("w2"))
lr=float(input("lr"))
t=float(input("t"))

a=nn(x,w1,w2,lr,t)

print(f"{'epoch':<6} {'w1':<10} {'w2':<10} {'lr':<10} {'h':<10} {'y':<10} {'loss':<10}")
for row in a:
    print(f"{row[0]:<6} {row[1]:<10.4f} {row[2]:<10.4f} {row[3]:<10.4f} {row[4]:<10.4f} {row[5]:<10.4f} {row[6]:<10.6f}")

#  Plot evolution 
epochs = [r[0] for r in a]
w1_vals = [r[1] for r in a]
w2_vals = [r[2] for r in a]
lr_vals = [r[3] for r in a]
loss_vals = [r[6] for r in a]

plt.figure(figsize=(12,6))

plt.subplot(2,2,1)
plt.plot(epochs, w1_vals, label="w1")
plt.xlabel("Epoch")
plt.ylabel("w1")
plt.legend()

plt.subplot(2,2,2)
plt.plot(epochs, w2_vals, label="w2", color="orange")
plt.xlabel("Epoch")
plt.ylabel("w2")
plt.legend()

plt.subplot(2,2,3)
plt.plot(epochs, lr_vals, label="Learning Rate", color="green")
plt.xlabel("Epoch")
plt.ylabel("lr")
plt.legend()

plt.subplot(2,2,4)
plt.plot(epochs, loss_vals, label="Loss", color="red")
plt.xlabel("Epoch")
plt.ylabel("Loss")
plt.yscale("log")  # log scale for better view
plt.legend()

plt.tight_layout()
plt.show()